<?php

declare(strict_types=1);

namespace App\Security\Forge;

use App\Forge\EndedSessions;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * Back-Channel Logout 1.0 §2.5 for a client of the forge: the provider has said that the session this
 * login was opened in has ended, so the next request the browser makes finds no session here either,
 * without the user going through anything.
 *
 * It runs right after the firewall has read the token of the session and before any controller: the
 * session of the provider is named in the "sid" of the ID token this login kept, and a session nobody
 * ended is left alone.
 */
#[AsEventListener(event: KernelEvents::REQUEST, priority: 7)]
final readonly class EndedSessionListener
{
    public function __construct(
        private TokenStorageInterface $tokens,
        private EndedSessions $ended,
    ) {
    }

    public function __invoke(RequestEvent $event): void
    {
        if (! $event->isMainRequest()) {
            return;
        }
        $token = $this->tokens->getToken();
        if ($token === null || $token->getFirewallName() !== ForgeAuthenticator::FIREWALL) {
            return;
        }

        $held = $token->hasAttribute(ForgeAuthenticator::TOKENS_ATTRIBUTE) ? $token->getAttribute(ForgeAuthenticator::TOKENS_ATTRIBUTE) : null;
        $claims = is_array($held) && is_array($held['id_token_claims'] ?? null) ? $held['id_token_claims'] : [];
        $session = $claims['sid'] ?? null;
        if (is_string($session) && $session !== '' && $this->ended->hasEnded($session)) {
            $this->tokens->setToken(null);
            $event->getRequest()->getSession()->remove('_security_' . ForgeAuthenticator::FIREWALL);
        }
    }
}
