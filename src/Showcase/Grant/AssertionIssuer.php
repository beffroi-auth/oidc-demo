<?php

declare(strict_types=1);

namespace App\Showcase\Grant;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Psr\Cache\CacheItemPoolInterface;

/**
 * The issuer this demonstration plays for the JWT bearer grant (RFC 7523 §2.1): an identity system the
 * tenant trusts, which vouches for a user of its own by signing an assertion. Its key is drawn once and
 * kept in a pool of this instance alone; the tenant pins its public half.
 */
final readonly class AssertionIssuer
{
    private const string KEY = 'showcase.assertion_issuer.key';

    public function __construct(
        private CacheItemPoolInterface $pool,
        private string $issuer,
    ) {
    }

    public function issuer(): string
    {
        return $this->issuer;
    }

    /**
     * The user this issuer vouches for, by the identifier it gives them.
     */
    public function subject(): string
    {
        return 'demo-user';
    }

    public function key(): JWK
    {
        $item = $this->pool->getItem(self::KEY);
        $held = $item->isHit() ? $item->get() : null;
        if (is_string($held)) {
            return JWK::createFromJson($held);
        }

        $key = JWKFactory::createECKey('P-256', ['alg' => 'ES256', 'use' => 'sig', 'kid' => bin2hex(random_bytes(8))]);
        $item->set((string) json_encode($key));
        $this->pool->save($item);

        return $key;
    }
}
