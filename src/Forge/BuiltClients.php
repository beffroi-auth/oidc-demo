<?php

declare(strict_types=1);

namespace App\Forge;

use Psr\Cache\CacheItemPoolInterface;

/**
 * The clients the forge built, in a pool of this application alone: one item per handle and one item
 * holding the handles, a pool being a store of values and not a list of keys.
 *
 * They are kept for a day at most, which is what the provider keeps a dynamic client that was used
 * (decision 0009): a built client whose registration the provider has removed is a client this store has
 * no reason to hold either, and the page says so rather than pretending it is still there.
 */
final readonly class BuiltClients
{
    private const string INDEX = 'forge.handles';

    private const int LIFETIME = 86400;

    public function __construct(
        private CacheItemPoolInterface $pool,
    ) {
    }

    public function keep(BuiltClient $client): void
    {
        $item = $this->pool->getItem($this->key($client->handle));
        $item->set($client->toArray());
        $item->expiresAfter(self::LIFETIME);
        $this->pool->save($item);

        $handles = $this->handles();
        $handles[$client->handle] = $client->builtAt;
        $this->writeIndex($handles);
    }

    /**
     * @throws ForgeException when no client of that handle was built, or the one that was has expired
     */
    public function of(string $handle): BuiltClient
    {
        $item = $this->pool->getItem($this->key($handle));
        $values = $item->isHit() ? $item->get() : null;
        if (! is_array($values)) {
            throw new ForgeException(sprintf('No client called "%s" was built here, or the one that was is gone.', $handle));
        }

        /** @var array<string, mixed> $values */
        return BuiltClient::fromArray($values);
    }

    public function holds(string $handle): bool
    {
        return $this->pool->getItem($this->key($handle))->isHit();
    }

    public function forget(string $handle): void
    {
        $this->pool->deleteItem($this->key($handle));
        $handles = $this->handles();
        unset($handles[$handle]);
        $this->writeIndex($handles);
    }

    /**
     * Every client still there, the last built first.
     *
     * @return list<BuiltClient>
     */
    public function all(): array
    {
        $handles = $this->handles();
        arsort($handles);

        $clients = [];
        foreach (array_keys($handles) as $handle) {
            if ($this->holds($handle)) {
                $clients[] = $this->of($handle);
            }
        }

        return $clients;
    }

    /**
     * @return array<string, int>
     */
    private function handles(): array
    {
        $item = $this->pool->getItem(self::INDEX);
        $handles = $item->isHit() ? $item->get() : [];

        /** @var array<string, int> $handles */
        return is_array($handles) ? $handles : [];
    }

    /**
     * @param array<string, int> $handles
     */
    private function writeIndex(array $handles): void
    {
        $item = $this->pool->getItem(self::INDEX);
        $item->set($handles);
        $item->expiresAfter(self::LIFETIME);
        $this->pool->save($item);
    }

    private function key(string $handle): string
    {
        return 'forge.client.' . $handle;
    }
}
