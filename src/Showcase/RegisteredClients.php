<?php

declare(strict_types=1);

namespace App\Showcase;

use App\Forge\Forge;
use App\Forge\ForgeException;
use Psr\Cache\CacheItemPoolInterface;

/**
 * The clients the tree registers for itself rather than through a composition of the forge, one per
 * handle: what was sent (RFC 7591 §2) and what the provider answered (§3.2.1), credentials included, kept
 * in a pool of this instance alone. The same registration under the same handle is never sent twice.
 */
final readonly class RegisteredClients
{
    public function __construct(
        private Forge $forge,
        private CacheItemPoolInterface $pool,
    ) {
    }

    /**
     * What the provider answered the registration held under this handle, registering it first when none
     * is held or the one held was sent otherwise.
     *
     * @param array<string, mixed> $registration
     * @param string|null $initialAccessToken the one of the forge when null
     *
     * @return array{client_id: string, client_secret: string|null, answer: array<string, mixed>}
     *
     * @throws ForgeException when the provider refuses it
     */
    public function ensure(string $handle, array $registration, ?string $initialAccessToken = null): array
    {
        $held = $this->held($handle);
        if ($held !== null && $held['sent'] === $registration) {
            return $held;
        }

        $answer = $this->forge->register($registration, $initialAccessToken);
        $clientId = $answer['client_id'] ?? null;
        if (! is_string($clientId) || $clientId === '') {
            throw new ForgeException(sprintf('The provider registered no client: %s', json_encode($answer)));
        }
        $secret = $answer['client_secret'] ?? null;
        unset($answer['client_secret'], $answer['registration_access_token']);
        $held = [
            'client_id' => $clientId,
            'client_secret' => is_string($secret) && $secret !== '' ? $secret : null,
            'answer' => $answer,
            'sent' => $registration,
        ];
        $item = $this->pool->getItem($this->key($handle));
        $item->set($held);
        $this->pool->save($item);

        return $held;
    }

    /**
     * RFC 7591 §3.2.1: the metadata the provider holds for the client, without what it issued to name and
     * manage it, which the panel shows apart or not at all.
     *
     * @return array<string, mixed>|null
     */
    public function metadataOf(string $handle): ?array
    {
        $answer = $this->held($handle)['answer'] ?? null;

        return $answer === null ? null : array_diff_key($answer, array_flip([
            'client_id',
            'client_id_issued_at',
            'client_secret_expires_at',
            'registration_client_uri',
        ]));
    }

    public function secretOf(string $handle): ?string
    {
        return $this->held($handle)['client_secret'] ?? null;
    }

    public function clientIdOf(string $handle): ?string
    {
        return $this->held($handle)['client_id'] ?? null;
    }

    /**
     * @return array{client_id: string, client_secret: string|null, answer: array<string, mixed>, sent: array<string, mixed>}|null
     */
    private function held(string $handle): ?array
    {
        $item = $this->pool->getItem($this->key($handle));
        $held = $item->isHit() ? $item->get() : null;

        /** @var array{client_id: string, client_secret: string|null, answer: array<string, mixed>, sent: array<string, mixed>}|null */
        return is_array($held) && is_string($held['client_id'] ?? null) ? $held : null;
    }

    private function key(string $handle): string
    {
        return 'showcase.client.' . $handle;
    }
}
