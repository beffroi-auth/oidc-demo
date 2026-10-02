<?php

declare(strict_types=1);

namespace App\Security\Fapi;

use Jose\Component\Core\JWK;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
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
 * The firewall of the last rung of the ladder (beffroi#201), which is not an "oidc_login" one: what this
 * rung asks of the provider is what `RP-04`, `RP-05`, `RP-06` and `RP-16` of the Symfony status document
 * say the authenticator cannot do yet.
 *
 * Two requests, as any authorization code flow: the entry point pushes a signed request and sends the
 * browser to the provider with nothing but a URI, and the callback reads a signed response, exchanges
 * the code against a bound token, opens the encrypted ID token and reads an encrypted UserInfo answer.
 * What each step proved is kept on the token, because the page of the rung exists to show it.
 */
final class FapiAuthenticator implements AuthenticatorInterface, AuthenticationEntryPointInterface
{
    use TargetPathTrait;

    public const FIREWALL = 'ladder_fapi';

    /**
     * What the token of this rung carries for the page to read: the tokens themselves, the key they are
     * bound to, and one line per thing the rung did that a plainer client does not.
     */
    public const TOKENS_ATTRIBUTE = 'fapi_tokens';

    public const OBSERVATIONS_ATTRIBUTE = 'fapi_observations';

    /**
     * What the entry point leaves in the session for the callback: what a client must remember between
     * the two requests, and nothing more (OIDC Core §3.1.2.1, RFC 7636 §4.1).
     */
    private const SESSION_KEY = 'fapi_login';

    public function __construct(
        private readonly FapiClient $client,
        private readonly UrlGeneratorInterface $urlGenerator,
    ) {
    }

    public function supports(Request $request): ?bool
    {
        return $request->getPathInfo() === $this->path('app_ladder_fapi_callback');
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        if (! $this->client->isConfigured()) {
            return new RedirectResponse($this->path('app_ladder_login', [
                'rung' => 'fapi',
            ]));
        }

        $verifier = self::random();
        $state = self::random();
        $nonce = self::random();
        $proofKey = FapiClient::proofKey();

        $pushed = $this->client->pushAuthorizationRequest([
            'response_type' => 'code',
            'client_id' => $this->client->clientId(),
            'redirect_uri' => $this->client->redirectUri(),
            'scope' => FapiClient::SCOPE,
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => self::base64Url(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
            // JARM §4.1: the response comes back as one signed parameter, whichever way it travels; the
            // provider resolves the alias to the mode of the response type (query.jwt here)
            'response_mode' => 'jwt',
        ]);

        $this->session($request)->set(self::SESSION_KEY, [
            'state' => $state,
            'nonce' => $nonce,
            'verifier' => $verifier,
            'proof_key' => $proofKey->all(),
            'request_uri' => $pushed['request_uri'],
            'request_object' => $pushed['request_object'],
        ]);

        return new RedirectResponse($this->client->authorizationUri($pushed['request_uri']));
    }

    public function authenticate(Request $request): Passport
    {
        $login = $this->session($request)->get(self::SESSION_KEY);
        if (! is_array($login)) {
            throw new FapiException('This callback answers no authorization request of this browser.');
        }

        $response = $request->query->get('response');
        if (! is_string($response) || $response === '') {
            throw new FapiException('The provider answered without the signed response JARM section 4.1 defines.');
        }

        $answer = $this->client->readAuthorizationResponse($response);
        if (! hash_equals((string) $login['state'], (string) ($answer['state'] ?? ''))) {
            throw new FapiException('The signed authorization response does not carry the state of this browser (RFC 6749 section 10.12).');
        }
        if (is_string($answer['error'] ?? null)) {
            throw new FapiException(sprintf('The provider refused the authorization request: %s.', $answer['error']));
        }
        $code = $answer['code'] ?? null;
        if (! is_string($code) || $code === '') {
            throw new FapiException('The signed authorization response carries no code.');
        }

        $proofKey = new JWK($login['proof_key']);
        $tokens = $this->client->exchange($code, (string) $login['verifier'], $proofKey);
        $idToken = $this->client->readIdToken((string) $tokens['id_token'], (string) $login['nonce']);
        $userInfo = $this->client->userInfo((string) $tokens['access_token'], $proofKey);

        $subject = (string) ($idToken['claims']['sub'] ?? '');
        if ($subject === '' || ! hash_equals($subject, (string) ($userInfo['claims']['sub'] ?? ''))) {
            throw new FapiException('The "sub" of UserInfo is not the one of the ID token (OIDC Core section 5.3.2).');
        }

        $this->session($request)->remove(self::SESSION_KEY);
        $claims = [...$userInfo['claims'], 'sub' => $subject];

        $passport = new SelfValidatingPassport(new UserBadge($subject, static fn (): OidcUser => OidcUser::fromClaims($claims), $claims));
        $passport->setAttribute(self::TOKENS_ATTRIBUTE, [
            'id_token' => $tokens['id_token'],
            'access_token' => $tokens['access_token'],
            'token_type' => $tokens['token_type'] ?? null,
            'id_token_claims' => $idToken['claims'],
            'request_object' => $login['request_object'],
            'request_uri' => $login['request_uri'],
            'authorization_response' => $response,
            'jkt' => FapiClient::thumbprint($proofKey),
        ]);
        $passport->setAttribute(self::OBSERVATIONS_ATTRIBUTE, self::observations($login, $tokens, $idToken, $userInfo, $proofKey));

        return $passport;
    }

    public function createToken(Passport $passport, string $firewallName): TokenInterface
    {
        $token = new PostAuthenticationToken($passport->getUser(), $firewallName, $passport->getUser()->getRoles());
        $token->setAttribute(self::TOKENS_ATTRIBUTE, $passport->getAttribute(self::TOKENS_ATTRIBUTE));
        $token->setAttribute(self::OBSERVATIONS_ATTRIBUTE, $passport->getAttribute(self::OBSERVATIONS_ATTRIBUTE));

        return $token;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $target = $this->getTargetPath($this->session($request), $firewallName);
        $this->removeTargetPath($this->session($request), $firewallName);

        return new RedirectResponse($target ?? $this->path('app_ladder_profile', [
            'rung' => 'fapi',
        ]));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $this->session($request)->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $exception);

        return new RedirectResponse($this->path('app_ladder_login', [
            'rung' => 'fapi',
        ]));
    }

    /**
     * One line per thing this rung did that the rungs below do not, in the order it happened.
     *
     * @param array<string, mixed> $login
     * @param array<string, mixed> $tokens
     * @param array{claims: array<string, mixed>, encrypted: bool, algorithm: string, encryption: string|null} $idToken
     * @param array{claims: array<string, mixed>, content_type: string, encrypted: bool} $userInfo
     *
     * @return list<array{string, string}>
     */
    private static function observations(array $login, array $tokens, array $idToken, array $userInfo, JWK $proofKey): array
    {
        $confirmation = $idToken['claims']['cnf']['jkt'] ?? null;
        $accessToken = self::payload((string) $tokens['access_token']);

        return [
            ['Pushed request (RFC 9126)', sprintf('request_uri %s, nothing of the request went through the browser', $login['request_uri'])],
            ['Signed request object (RFC 9101)', sprintf('ES256, %d characters, pushed to the /par endpoint', strlen((string) $login['request_object']))],
            ['Signed response (JARM)', 'a single "response" parameter, verified against the JWK Set of the provider'],
            ['Client authentication (RFC 7523)', 'private_key_jwt: a signed assertion, no shared secret'],
            ['Bound token (RFC 9449)', sprintf(
                'token_type %s, cnf.jkt %s, a proof signed for every request',
                $tokens['token_type'] ?? '?',
                is_string($accessToken['cnf']['jkt'] ?? null) ? $accessToken['cnf']['jkt'] : (is_string($confirmation) ? $confirmation : '?'),
            )],
            ['Encrypted ID token (OIDC Core §3.1.3.7)', $idToken['encrypted']
                ? sprintf('JWE %s, then JWS %s', $idToken['encryption'] ?? '?', $idToken['algorithm'])
                : sprintf('signed %s, not encrypted', $idToken['algorithm'])],
            ['UserInfo (OIDC Core §5.3.2)', sprintf(
                '%s%s, sub compared with the one of the ID token',
                $userInfo['content_type'],
                $userInfo['encrypted'] ? ', encrypted then signed' : '',
            )],
            ['Key of the proof', FapiClient::thumbprint($proofKey)],
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private static function payload(string $token): array
    {
        $parts = explode('.', $token);
        $claims = count($parts) === 3 ? json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), true) : null;

        return is_array($claims) ? $claims : [];
    }

    /**
     * @param array<string, mixed> $parameters
     */
    private function path(string $route, array $parameters = []): string
    {
        return $this->urlGenerator->generate($route, $parameters);
    }

    private function session(Request $request): SessionInterface
    {
        return $request->getSession();
    }

    private static function random(): string
    {
        return bin2hex(random_bytes(32));
    }

    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
