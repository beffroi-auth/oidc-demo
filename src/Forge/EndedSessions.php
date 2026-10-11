<?php

declare(strict_types=1);

namespace App\Forge;

use Psr\Cache\CacheItemPoolInterface;

/**
 * The sessions of the provider that have ended, as its back channel said so (Back-Channel Logout 1.0
 * §2.5): one item per session, kept long enough that the login it ended cannot outlive it.
 *
 * It is a store of this instance alone, like the one `oidc_login` keeps for the "main" firewall, so two
 * demonstrations running side by side on one machine do not end each other's sessions.
 */
final readonly class EndedSessions
{
    private const int LIFETIME = 86400;

    public function __construct(
        private CacheItemPoolInterface $pool,
    ) {
    }

    public function end(string $session): void
    {
        $item = $this->pool->getItem($this->key($session));
        $item->set(true);
        $item->expiresAfter(self::LIFETIME);
        $this->pool->save($item);
    }

    public function hasEnded(string $session): bool
    {
        return $this->pool->getItem($this->key($session))->isHit();
    }

    private function key(string $session): string
    {
        return 'forge.ended.' . hash('xxh128', $session);
    }
}
