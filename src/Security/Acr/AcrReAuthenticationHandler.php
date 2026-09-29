<?php

declare(strict_types=1);

namespace App\Security\Acr;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\Authorization\AccessDeniedHandlerInterface;
use Symfony\Component\Security\Http\EntryPoint\ReAuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\SecurityRequestAttributes;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

/**
 * Sends a session that lacks the authentication context class back to the provider for a stronger
 * login, instead of answering the plain 403 the firewall would.
 *
 * ExceptionListener starts a re-authentication by itself only when the denied attribute is
 * IS_AUTHENTICATED_RECENTLY or IS_AUTHENTICATED_VERY_RECENTLY, two names it holds itself; an
 * application whose own attribute was denied has to call the entry point, which is what this does.
 * Symfony pull request #66235 moves that list to the entry point, and this handler then becomes a
 * decorated entry point answering for AcrVoter::REQUIRES_PHR.
 *
 * What is asked of the provider is not set here: startReAuthentication() sends "prompt=login" and the
 * previous ID token as "id_token_hint", and AcrValuesListener adds "acr_values" from the attribute this
 * writes on the request.
 */
final class AcrReAuthenticationHandler implements AccessDeniedHandlerInterface
{
    use TargetPathTrait;

    public function __construct(
        private readonly ReAuthenticationEntryPointInterface $entryPoint,
        private readonly TokenStorageInterface $tokenStorage,
        private readonly string $firewallName,
    ) {
    }

    public function handle(Request $request, AccessDeniedException $accessDeniedException): ?Response
    {
        // the whole attribute list, not a search in it: an access_control rule is decided on all of its
        // roles at once, so a denial of [ROLE_ADMIN, REQUIRES_PHR] does not say which one failed, and a
        // stronger login would not help a user who simply lacks the role
        if ($accessDeniedException->getAttributes() !== [AcrVoter::REQUIRES_PHR]) {
            return null;
        }

        $token = $this->tokenStorage->getToken();
        if ($token === null) {
            return null;
        }

        // so that the provider sends the user back to the page that was asked for, and not to the
        // default target path of the firewall
        if ($request->hasSession() && $request->isMethodSafe() && ! $request->isXmlHttpRequest()) {
            $this->saveTargetPath($request->getSession(), $this->firewallName, $request->getUri());
        }

        $request->attributes->set(SecurityRequestAttributes::RE_AUTHENTICATION_ATTRIBUTE, AcrVoter::REQUIRES_PHR);

        return $this->entryPoint->startReAuthentication($request, $token);
    }
}
