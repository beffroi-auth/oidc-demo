<?php

declare(strict_types=1);

namespace App\Security\Acr;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\Security\Http\Event\OidcAuthorizationRequestEvent;
use Symfony\Component\Security\Http\SecurityRequestAttributes;

/**
 * Asks the provider for the authentication context class the route needs (OIDC Core §3.1.2.1).
 *
 * "acr_values" is not a parameter the authenticator manages, so a listener shapes it; it is added only on
 * the re-authentication AcrReAuthenticationHandler started, which the attribute it wrote on the request
 * says, and not on an ordinary login, which is free to come back with any class.
 */
#[AsEventListener]
final class AcrValuesListener
{
    /**
     * @param list<string> $acceptedClasses the same classes AcrVoter grants on, asked of the provider in
     *                                      order of preference as a space-delimited list
     */
    public function __construct(
        private readonly array $acceptedClasses,
    ) {
    }

    public function __invoke(OidcAuthorizationRequestEvent $event): void
    {
        $attribute = $event->getRequest()->attributes->get(SecurityRequestAttributes::RE_AUTHENTICATION_ATTRIBUTE);
        if ($attribute !== AcrVoter::REQUIRES_PHR) {
            return;
        }

        $event->setParam('acr_values', implode(' ', $this->acceptedClasses));
    }
}
