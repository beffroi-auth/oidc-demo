<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\User\OidcUser;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Symfony\Component\Security\Http\Oidc\OidcDiscovery;

/**
 * Exercises the "oidc_login" authenticator of Symfony against the provider this demonstration is written
 * for, whose issuer is the only thing it is configured with: the profile of a signed-in user, the vault
 * that asks for a phishing-resistant sign-in, and the page a failed login lands on. The ladder of clients
 * serves the home page (LadderController), and the routes behind an access token serve the resource server
 * (ApiController).
 */
final class DemoController extends AbstractController
{
    /**
     * @param string        $providerUri The OIDC issuer the firewall is configured with, shown as-is on the pages
     * @param OidcDiscovery $discovery   The discovery service of the "main" firewall, holding the cached document
     */
    public function __construct(
        private readonly string $providerUri,
        private readonly string $clientId,
        private readonly OidcDiscovery $discovery,
    ) {
    }

    /**
     * Protected by access_control: an anonymous visitor lands on the authenticator's
     * entry point, which starts the Authorization Code Flow.
     */
    #[Route('/profile', name: 'app_profile')]
    public function profile(Security $security): Response
    {
        $user = $this->getUser();
        \assert($user instanceof OidcUser);

        $token = $security->getToken();

        return $this->render('demo/profile.html.twig', [
            'user' => $user,
            'user_class' => $user::class,
            'claims' => $this->standardClaims($user),
            'additional_claims' => $user->getAdditionalClaims(),
            'id_token' => $token?->getAttribute('oidc_id_token'),
            'access_token' => $token?->getAttribute('oidc_access_token'),
            'id_token_claims' => self::decodeJwt($token?->getAttribute('oidc_id_token')),
            'access_token_claims' => self::decodeJwt($token?->getAttribute('oidc_access_token')),
            'provider_uri' => $this->providerUri,
        ]);
    }

    /**
     * Protected by access_control with IS_AUTHENTICATED_IN_CONTEXT:phr: a session whose ID
     * token carries another "acr" is sent back to the provider for a passkey. The page shows
     * what the authenticator recorded on the security token from the new ID token.
     */
    #[Route('/vault', name: 'app_vault')]
    public function vault(Security $security): Response
    {
        $token = $security->getToken();
        $idTokenClaims = self::decodeJwt($token?->getAttribute('oidc_id_token'));

        return $this->render('demo/vault.html.twig', [
            'acr' => $token?->getAuthenticationContextClass(),
            'proofs' => $token?->getAuthenticationProofs() ?? [],
            'auth_time' => $idTokenClaims['auth_time'] ?? null,
            'amr' => $idTokenClaims['amr'] ?? null,
            'sid' => $idTokenClaims['sid'] ?? null,
            'id_token_claims' => $idTokenClaims,
        ]);
    }

    /**
     * Landing page of both "login_path" and "failure_path": it reports why the last
     * attempt failed instead of bouncing the visitor back to the provider.
     */
    #[Route('/login', name: 'app_login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        return $this->render('demo/login.html.twig', [
            'error' => $authenticationUtils->getLastAuthenticationError(),
            'provider_uri' => $this->providerUri,
        ]);
    }

    /**
     * @return array<string, mixed>
     */
    private function standardClaims(OidcUser $user): array
    {
        return array_filter([
            'sub' => $user->getSub(),
            'name' => $user->getName(),
            'given_name' => $user->getGivenName(),
            'family_name' => $user->getFamilyName(),
            'middle_name' => $user->getMiddleName(),
            'nickname' => $user->getNickname(),
            'preferred_username' => $user->getPreferredUsername(),
            'profile' => $user->getProfile(),
            'picture' => $user->getPicture(),
            'website' => $user->getWebsite(),
            'email' => $user->getEmail(),
            'email_verified' => $user->getEmailVerified(),
            'gender' => $user->getGender(),
            'birthdate' => $user->getBirthdate(),
            'zoneinfo' => $user->getZoneinfo(),
            'locale' => $user->getLocale(),
            'phone_number' => $user->getPhoneNumber(),
            'phone_number_verified' => $user->getphoneNumberVerified(),
            'address' => $user->getAddress(),
            'updated_at' => $user->getUpdatedAt()?->format(\DATE_ATOM),
        ], static fn ($value) => null !== $value);
    }

    /**
     * Decodes the payload of a JWT for display only: the ID token was already validated
     * by the authenticator, and the access token is opaque to this application.
     *
     * @return array<string, mixed>|null
     */
    private static function decodeJwt(?string $jwt): ?array
    {
        if (null === $jwt) {
            return null;
        }

        $parts = explode('.', $jwt);

        if (3 !== \count($parts)) {
            return null;
        }

        $payload = base64_decode(strtr($parts[1], '-_', '+/'), true);

        if (false === $payload) {
            return null;
        }

        return json_decode($payload, true, 512, \JSON_THROW_ON_ERROR | \JSON_OBJECT_AS_ARRAY);
    }
}
