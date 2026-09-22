<?php

declare(strict_types=1);

namespace App\Security\Fapi;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Event\LogoutEvent;

/**
 * RP-Initiated Logout 1.0 §2 for the last rung of the ladder, which is not an "oidc_login" firewall and
 * therefore has none of its listeners: logging out of this application ends the session at the provider
 * too, the ID token of the login saying which session it is.
 */
// on the dispatcher of that firewall and of no other: every firewall has one, and a listener of the
// application dispatcher would answer the logout of every rung
#[AsEventListener(event: LogoutEvent::class, dispatcher: 'security.event_dispatcher.' . FapiAuthenticator::FIREWALL)]
final class FapiLogoutListener
{
    public function __construct(
        private readonly FapiClient $client,
        private readonly UrlGeneratorInterface $urlGenerator,
    ) {
    }

    public function __invoke(LogoutEvent $event): void
    {
        $token = $event->getToken();
        $tokens = $token?->hasAttribute(FapiAuthenticator::TOKENS_ATTRIBUTE) === true
            ? $token->getAttribute(FapiAuthenticator::TOKENS_ATTRIBUTE)
            : null;
        $idToken = is_array($tokens) ? $tokens['id_token'] ?? null : null;
        if (! is_string($idToken) || $idToken === '') {
            return;
        }

        $uri = $this->client->endSessionUri($idToken, $this->urlGenerator->generate('app_home', [], UrlGeneratorInterface::ABSOLUTE_URL));
        if ($uri !== null) {
            $event->setResponse(new RedirectResponse($uri));
        }
    }
}
