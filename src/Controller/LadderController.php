<?php

declare(strict_types=1);

namespace App\Controller;

use App\Ladder\Rungs;
use App\Security\Fapi\FapiAuthenticator;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\User\OidcUser;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

/**
 * The ladder of demonstration clients (beffroi#201): one page to choose a rung, one page per rung once it
 * signed in, and the two routes the last rung needs of its own.
 *
 * Every rung serves the same page, which is the point: what changes from one to the next is what the
 * client registered and what travelled, not what the application does with the identity it obtained.
 */
final class LadderController extends AbstractController
{
    public function __construct(
        private readonly string $providerUri,
    ) {
    }

    #[Route('/', name: 'app_home', methods: ['GET'])]
    public function ladder(): Response
    {
        return $this->render('ladder/index.html.twig', [
            'rungs' => Rungs::RUNGS,
            'provider_uri' => $this->providerUri,
        ]);
    }

    /**
     * Behind the firewall of its rung: reaching it without a session starts the flow of that rung, which
     * is the whole demonstration.
     */
    #[Route('/c/{rung}/profile', name: 'app_ladder_profile', requirements: ['rung' => '[a-z-]+'], methods: ['GET'])]
    public function profile(string $rung, Security $security): Response
    {
        $definition = Rungs::of($rung);
        $token = $security->getToken();
        $user = $token?->getUser();

        return $this->render('ladder/profile.html.twig', [
            'rung' => $rung,
            'definition' => $definition,
            'user' => $user,
            'claims' => $user instanceof OidcUser ? $user->getAdditionalClaims() : [],
            // the rungs of "oidc_login" keep their tokens on the security token under these names; the
            // last rung keeps its own, so neither is asked for without being there
            'id_token' => $token?->hasAttribute('oidc_id_token') === true ? $token->getAttribute('oidc_id_token') : null,
            'access_token' => $token?->hasAttribute('oidc_access_token') === true ? $token->getAttribute('oidc_access_token') : null,
            'fapi_tokens' => $token?->hasAttribute(FapiAuthenticator::TOKENS_ATTRIBUTE) ? $token->getAttribute(FapiAuthenticator::TOKENS_ATTRIBUTE) : null,
            'observations' => $token?->hasAttribute(FapiAuthenticator::OBSERVATIONS_ATTRIBUTE) ? $token->getAttribute(FapiAuthenticator::OBSERVATIONS_ATTRIBUTE) : [],
            // RFC 9396 section 7: what the access token says was granted beyond its scopes, read here so that
            // the page shows it rather than showing a token with it buried inside. A client is not a resource
            // server and verifies nothing of a token it merely carries: this is read to be printed.
            'authorization_details' => self::grantedDetails($token?->hasAttribute('oidc_access_token') === true ? $token->getAttribute('oidc_access_token') : null),
            'provider_uri' => $this->providerUri,
        ]);
    }

    /**
     * The "authorization_details" of a self-contained access token (RFC 9068 section 2.2), or none: an opaque
     * token says nothing to whoever reads it, and a token of a rung that asked for no detail carries none.
     *
     * @return list<array<string, mixed>>
     */
    private static function grantedDetails(mixed $accessToken): array
    {
        if (!\is_string($accessToken)) {
            return [];
        }
        $parts = \explode('.', $accessToken);
        if (3 !== \count($parts)) {
            return [];
        }
        $payload = \json_decode((string) \base64_decode(\strtr($parts[1], '-_', '+/'), true), true);
        $details = \is_array($payload) ? ($payload['authorization_details'] ?? null) : null;

        return \is_array($details) ? \array_values(\array_filter($details, '\is_array')) : [];
    }

    /**
     * Where a rung sends a login it refused, so that the reason is read instead of being bounced back to
     * the provider for another try.
     */
    #[Route('/c/{rung}/login', name: 'app_ladder_login', requirements: ['rung' => '[a-z-]+'], methods: ['GET'])]
    public function login(string $rung, AuthenticationUtils $authenticationUtils): Response
    {
        return $this->render('ladder/login.html.twig', [
            'rung' => $rung,
            'definition' => Rungs::of($rung),
            'error' => $authenticationUtils->getLastAuthenticationError(),
            'provider_uri' => $this->providerUri,
        ]);
    }

    /**
     * The callback of the last rung. Nothing runs here: the authenticator of that firewall answers the
     * request before any controller does, and the route exists so that the path has a name.
     */
    #[Route('/c/fapi/callback', name: 'app_ladder_fapi_callback', methods: ['GET'])]
    public function fapiCallback(): Response
    {
        throw new \LogicException('The FAPI authenticator answers this path.');
    }

    /**
     * Front-Channel Logout 1.0 §3: the logout page of the provider loads this URI in a frame, in the
     * browser of the user and with its cookies, naming the session that ended. The rung ends the session
     * it opened for that one, and only that one: the other rungs keep theirs, each firewall holding its
     * own in the session of this application.
     */
    #[Route('/c/{rung}/frontchannel-logout', name: 'app_ladder_frontchannel_logout', requirements: ['rung' => '[a-z-]+'], methods: ['GET'])]
    public function frontChannelLogout(string $rung, Request $request): Response
    {
        $definition = Rungs::of($rung);
        $session = $request->getSession();
        $key = '_security_' . $definition['firewall'];
        $ended = false;

        // the provider says which session ended; a request that names another issuer is not one of its
        // logouts, and one that names no session is not one this client registered for
        if ($request->query->get('iss') === $this->providerUri && $request->query->get('sid') !== null && $session->has($key)) {
            $session->remove($key);
            $ended = true;
        }

        return $this->render('ladder/frontchannel.html.twig', [
            'rung' => $rung,
            'definition' => $definition,
            'ended' => $ended,
            'sid' => $request->query->get('sid'),
        ]);
    }
}
