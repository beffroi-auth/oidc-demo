<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Authenticator\AccessTokenAuthenticator;

/**
 * The resource server half of the demonstration: the same answer behind five firewalls, which
 * differ only in how the access token that reached them was checked (config/packages/security.yaml).
 *
 * Nothing here knows which of the five it is serving: the badge of the authenticated token is what
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
