<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Authenticator\AccessTokenAuthenticator;

/**
 * The resource server half of the demonstration: the same answer behind five firewalls, which
 * differ only in how the access token that reached them was checked (config/packages/security.yaml).
 *
 * Nothing here knows which of the first five it is serving: the badge of the authenticated token is what
 * each firewall built from the claims it obtained, by introspection or by verifying a JWT, and the
 * point of the demonstration is that the answer does not change.
 */
final class ApiController extends AbstractController
{
    /**
     * RFC 7662: the token is described by the provider, whatever its shape.
     */
    #[Route('/api/me', name: 'api_me', methods: ['GET'])]
    public function me(Security $security): JsonResponse
    {
        return $this->identity($security, 'introspection');
    }

    /**
     * RFC 9701: the same answer, signed by the provider and verified against the keys its RFC 8414
     * metadata points at.
     */
    #[Route('/api/me/signed', name: 'api_me_signed', methods: ['GET'])]
    public function signed(Security $security): JsonResponse
    {
        return $this->identity($security, 'introspection, signed response');
    }

    /**
     * RFC 9068: an "at+jwt" verified here, without asking the provider anything.
     */
    #[Route('/api/me/offline', name: 'api_me_offline', methods: ['GET'])]
    public function offline(Security $security): JsonResponse
    {
        return $this->identity($security, 'at+jwt verified offline');
    }

    /**
     * RFC 9449: an "at+jwt" bound to a key, verified here, and the request proving possession of that key.
     */
    #[Route('/api/me/dpop', name: 'api_me_dpop', methods: ['GET'])]
    public function dpop(Security $security): JsonResponse
    {
        return $this->identity($security, 'at+jwt verified offline, bound by DPoP');
    }

    /**
     * RFC 9449 through RFC 7662: the binding of an opaque token is what the introspection response says it
     * is ("cnf"), and the proof is checked against that.
     */
    #[Route('/api/me/dpop/introspected', name: 'api_me_dpop_introspected', methods: ['GET'])]
    public function dpopIntrospected(Security $security): JsonResponse
    {
        return $this->identity($security, 'introspection, bound by DPoP');
    }

    /**
     * RFC 8693 section 4.1: a token a gateway holds for the subject of a service, presented to the resource
     * it is addressed to. What this application can know of it is what the token handler of Symfony hands
     * over, the subject and the scopes; who is acting for that subject is in the token and is dropped on the
     * way, so it is read back here from the payload the firewall has already verified. A resource server
     * that must know through whom it was reached cannot get it from the authenticator.
     */
    #[Route('/api/service', name: 'api_service', methods: ['GET'])]
    public function service(Security $security, Request $request): JsonResponse
    {
        $answer = $this->identity($security, 'at+jwt verified offline, addressed to this resource');
        $claims = self::claimsOf($request);
        $answer->setData([
            ...(array) json_decode((string) $answer->getContent(), true),
            'aud' => $claims['aud'] ?? null,
            'act' => $claims['act'] ?? null,
            'read_from' => 'the payload of the token, the authenticator passing neither aud nor act',
        ]);

        return $answer;
    }

    /**
     * The claims of the bearer token of this request, whose signature the firewall has already verified:
     * nothing is believed here that was not believed there, and nothing is verified twice.
     *
     * @return array<string, mixed>
     */
    private static function claimsOf(Request $request): array
    {
        $parts = explode('.', (string) preg_replace('/^Bearer\s+/i', '', (string) $request->headers->get('Authorization')));
        if (3 !== count($parts)) {
            return [];
        }
        $payload = json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), true);

        return is_array($payload) ? $payload : [];
    }

    private function identity(Security $security, string $checkedBy): JsonResponse
    {
        $token = $security->getToken();
        $user = $token?->getUser();

        return new JsonResponse([
            'sub' => $token?->getUserIdentifier(),
            'user_class' => null === $user ? null : $user::class,
            'scope' => $token?->getAttribute(AccessTokenAuthenticator::SCOPE_ATTRIBUTE) ?? [],
            'checked_by' => $checkedBy,
        ]);
    }
}
