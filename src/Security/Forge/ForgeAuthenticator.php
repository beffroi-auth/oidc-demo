<?php

declare(strict_types=1);

namespace App\Security\Forge;

use App\Forge\BuiltClients;
use App\Forge\Flow\FlowClient;
use App\Forge\ForgeException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\OidcUser;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\SecurityRequestAttributes;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

/**
 * The one firewall of the clients the forge builds (beffroi#582), in place of the five "oidc_login" ones
 * the ladder of rungs had: a client born at runtime cannot be a firewall of the configuration, so a
 * composition is always played by this authenticator.
 *
 * It decides nothing of the flow. Which client this request belongs to is the handle in its path, what
 * that client does is its composition, and the two requests of the flow are FlowClient::start() and
 * FlowClient::finish(). What each step proved is kept on the token, because the page of a built client
 * exists to show it.
 *
 * `oidc_login` stays the reference client of the core on the "main" firewall, and what it cannot do is
 * still written down: `RP-04`, `RP-05`, `RP-06` and `RP-16` of the Symfony status document are open, and
 * nothing here closes them.
 */
final class ForgeAuthenticator implements AuthenticatorInterface, AuthenticationEntryPointInterface
{
    use TargetPathTrait;

    public const string FIREWALL = 'forge';

    /**
     * What the token of a built client carries for its page to read: which client signed in, what it
     * holds, and every hop of the flow it played.
     */
    public const string HANDLE_ATTRIBUTE = 'forge_handle';

    public const string TOKENS_ATTRIBUTE = 'forge_tokens';

    public const string HOPS_ATTRIBUTE = 'forge_hops';

    public function __construct(
        private readonly FlowClient $flow,
        private readonly BuiltClients $clients,
        private readonly UrlGeneratorInterface $urlGenerator,
    ) {
    }

    public function supports(Request $request): ?bool
    {
        return $request->attributes->get('_route') === 'app_forge_callback';
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        $handle = $this->handle($request);
        if ($handle === null || ! $this->clients->holds($handle)) {
            return new RedirectResponse($this->urlGenerator->generate('app_home'));
        }

        try {
            $started = $this->flow->start($this->clients->of($handle));
        } catch (ForgeException $exception) {
            $this->session($request)->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, new CustomUserMessageAuthenticationException($exception->getMessage()));

            return new RedirectResponse($this->loginPath($handle));
        }

        $this->session($request)->set($this->sessionKey($handle), $started->remembered);

        return new RedirectResponse($started->url);
    }

    public function authenticate(Request $request): Passport
    {
        $handle = $this->handle($request) ?? throw new CustomUserMessageAuthenticationException('This callback belongs to no client of the forge.');
        $remembered = $this->session($request)->get($this->sessionKey($handle));
        if (! is_array($remembered)) {
            throw new CustomUserMessageAuthenticationException('This callback answers no authorization request of this browser.');
        }

        try {
            $client = $this->clients->of($handle);
            $identity = $this->flow->finish($client, $request, $remembered);
        } catch (ForgeException $exception) {
            throw new CustomUserMessageAuthenticationException($exception->getMessage(), previous: $exception);
        }

        $this->session($request)->remove($this->sessionKey($handle));
        $claims = $identity->claims;

        $passport = new SelfValidatingPassport(new UserBadge(
            $identity->subject,
            static fn (): OidcUser => OidcUser::fromClaims($claims),
            $claims,
        ));
        $passport->setAttribute(self::HANDLE_ATTRIBUTE, $handle);
        $passport->setAttribute(self::TOKENS_ATTRIBUTE, $identity->tokens);
        $passport->setAttribute(self::HOPS_ATTRIBUTE, $identity->hops);

        return $passport;
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        $token = new PostAuthenticationToken($passport->getUser(), $firewallName, $passport->getUser()->getRoles());
        $token->setAttribute(self::HANDLE_ATTRIBUTE, $passport->getAttribute(self::HANDLE_ATTRIBUTE));
        $token->setAttribute(self::TOKENS_ATTRIBUTE, $passport->getAttribute(self::TOKENS_ATTRIBUTE));
        $token->setAttribute(self::HOPS_ATTRIBUTE, $passport->getAttribute(self::HOPS_ATTRIBUTE));

        return $token;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $handle = (string) $token->getAttribute(self::HANDLE_ATTRIBUTE);
        $target = $this->getTargetPath($this->session($request), $firewallName);
        $this->removeTargetPath($this->session($request), $firewallName);

        return new RedirectResponse($target ?? $this->urlGenerator->generate('app_forge_profile', [
            'handle' => $handle,
        ]));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $this->session($request)->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $exception);
        $handle = $this->handle($request);

        return new RedirectResponse($handle === null
            ? $this->urlGenerator->generate('app_home')
            : $this->loginPath($handle));
    }

    /**
     * Which built client this request belongs to: the handle of its route, every route of a built client
     * carrying one.
     */
    private function handle(Request $request): ?string
    {
        $parameters = $request->attributes->get('_route_params');
        $handle = is_array($parameters) ? ($parameters['handle'] ?? null) : null;

        return is_string($handle) && $handle !== '' ? $handle : null;
    }

    private function loginPath(string $handle): string
    {
        return $this->urlGenerator->generate('app_forge_login', [
            'handle' => $handle,
        ]);
    }

    /**
     * What the entry point leaves for the callback, under the handle of the client it belongs to: two
     * built clients signing in one after the other in one browser remember their own request, and the
     * second never answers the first (OIDC Core §3.1.2.1, RFC 7636 §4.1).
     */
    private function sessionKey(string $handle): string
    {
        return 'forge.login.' . $handle;
    }

    private function session(Request $request): SessionInterface
    {
        return $request->getSession();
    }
}
