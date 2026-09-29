<?php

declare(strict_types=1);

namespace App\Security\Acr;

use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Vote;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * A route that needs an authentication context class rather than a role: the session is granted only
 * when the provider asserted one of the classes named here (OpenID Connect EAP ACR Values 1.0).
 *
 * "oidc_login" records the "acr" claim of the ID token as the "oidc_acr" attribute of the security
 * token, which is what this reads; the policy, which classes answer for the route, lives here and in
 * config/services.yaml, in one place rather than on every route.
 */
final class AcrVoter extends Voter
{
    /**
     * The attribute of the access_control rule. It is not one of the IS_AUTHENTICATED_* names, which
     * AuthenticatedVoter owns, so the denial it produces is this application's to answer:
     * AcrReAuthenticationHandler is what answers it.
     */
    public const REQUIRES_PHR = 'REQUIRES_PHR';

    /**
     * @param list<string> $acceptedClasses the classes that answer for the attribute, in the order
     *                                      they are asked of the provider as "acr_values"
     */
    public function __construct(
        private readonly array $acceptedClasses,
    ) {
    }

    protected function supports(string $attribute, mixed $subject): bool
    {
        return $attribute === self::REQUIRES_PHR;
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token, ?Vote $vote = null): bool
    {
        $class = $token->hasAttribute('oidc_acr') ? $token->getAttribute('oidc_acr') : null;

        if (! is_string($class) || $class === '') {
            $vote?->addReason('The provider asserted no authentication context class.');

            return false;
        }

        if (! in_array($class, $this->acceptedClasses, true)) {
            $vote?->addReason(sprintf('The authentication context class is "%s".', $class));

            return false;
        }

        return true;
    }
}
