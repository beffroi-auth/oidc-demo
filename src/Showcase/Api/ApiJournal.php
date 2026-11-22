<?php

declare(strict_types=1);

namespace App\Showcase\Api;

use Psr\Cache\CacheItemPoolInterface;

/**
 * The last calls the API of /api/v1 answered, newest first: what was asked, what was answered, and how the
 * token of the call was checked. The API keeps nothing of a request, so this is the one place that says
 * what it did, and the proof the panels of the API show.
 */
final readonly class ApiJournal
{
    private const string KEY = 'showcase.api.journal';
    private const int KEPT = 12;

    public function __construct(
        private CacheItemPoolInterface $pool,
    ) {
    }

    /**
     * @param array{at: int, call: string, status: int, how: string|null, client_id: string|null, sub: string|null, scope: string|null, error: string|null} $call
     */
    public function record(array $call): void
    {
        $item = $this->pool->getItem(self::KEY);
        $item->set(array_slice([$call, ...$this->calls()], 0, self::KEPT));
        $this->pool->save($item);
    }

    /**
     * @return list<array{at: int, call: string, status: int, how: string|null, client_id: string|null, sub: string|null, scope: string|null, error: string|null}>
     */
    public function calls(): array
    {
        $item = $this->pool->getItem(self::KEY);
        $calls = $item->isHit() ? $item->get() : [];

        /** @var list<array{at: int, call: string, status: int, how: string|null, client_id: string|null, sub: string|null, scope: string|null, error: string|null}> */
        return is_array($calls) ? $calls : [];
    }
}
