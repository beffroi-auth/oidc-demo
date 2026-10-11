<?php

declare(strict_types=1);

namespace App\Security\Forge;

use App\Forge\BuiltClients;
use App\Forge\Flow\FlowClient;
use App\Forge\ForgeException;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Event\LogoutEvent;

/**
 * RP-Initiated Logout 1.0 §2 for a client of the forge, which is not an "oidc_login" firewall and has
 * none of its listeners: signing out of this application ends the session at the provider too, the ID
 * token of the login saying which session that is.
 */
// on the dispatcher of that firewall and of no other: a listener of the application dispatcher would
// answer the logout of the reference client too
#[AsEventListener(event: LogoutEvent::class, dispatcher: 'security.event_dispatcher.' . ForgeAuthenticator::FIREWALL)]
final readonly class ForgeLogoutListener
{
    public function __construct(
        private FlowClient $flow,
        private BuiltClients $clients,
        private UrlGeneratorInterface $urlGenerator,
    ) {
    }

    public function __invoke(LogoutEvent $event): void
    {
        $token = $event->getToken();
        if ($token === null || ! $token->hasAttribute(ForgeAuthenticator::HANDLE_ATTRIBUTE)) {
            return;
        }

        $held = $token->hasAttribute(ForgeAuthenticator::TOKENS_ATTRIBUTE) ? $token->getAttribute(ForgeAuthenticator::TOKENS_ATTRIBUTE) : null;
        $idToken = is_array($held) ? $held['id_token'] ?? null : null;
        $handle = (string) $token->getAttribute(ForgeAuthenticator::HANDLE_ATTRIBUTE);
        if (! is_string($idToken) || $idToken === '' || ! $this->clients->holds($handle)) {
            return;
        }

        try {
            $url = $this->flow->endSessionUrl(
                $this->clients->of($handle),
                $idToken,
                $this->urlGenerator->generate('app_home', [], UrlGeneratorInterface::ABSOLUTE_URL),
            );
        } catch (ForgeException) {
            return;
        }
        if ($url !== null) {
            $event->setResponse(new RedirectResponse($url));
        }
    }
}
