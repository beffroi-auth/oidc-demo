<?php

declare(strict_types=1);

namespace App\Showcase\Grant;

use App\Forge\ForgeException;
use App\Showcase\Runs;
use App\Showcase\Waiting;
use Psr\Clock\ClockInterface;

/**
 * Asking the token endpoint whether the user has answered yet, as a device (RFC 8628 §3.4, §3.5) and a
 * client of CIBA in poll mode (CIBA Core §7.3, §11) both do: never sooner than the interval the provider
 * named, five seconds more each time it says "slow_down", until it answers a token or an error that is
 * not "authorization_pending".
 */
final readonly class TokenPolling
{
    public function __construct(
        private ProviderEndpoint $endpoint,
        private Waiting $waiting,
        private Runs $runs,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @param list<array{label: string, what: string, payload: string|null}> $proofs what led to the wait
     * @param array<string, mixed> $shown what the panel shows meanwhile
     */
    public function wait(string $handle, int $interval, int $expiresIn, array $proofs, array $shown): void
    {
        $now = $this->clock->now()->getTimestamp();
        $this->runs->forget($handle);
        $this->waiting->start($handle, [
            ...$shown,
            'interval' => $interval,
            'next_at' => $now + $interval,
            'expires_at' => $now + $expiresIn,
            'polls' => 0,
            'proofs' => $proofs,
        ]);
    }

    /**
     * @param array<string, string> $form
     *
     * @return bool true once the run ended
     */
    public function poll(string $handle, array $form, string $clientId, ?string $secret): bool
    {
        $state = $this->waiting->of($handle);
        if ($state === null) {
            return true;
        }
        /** @var list<array{label: string, what: string, payload: string|null}> $proofs */
        $proofs = is_array($state['proofs'] ?? null) ? $state['proofs'] : [];
        $interval = is_int($state['interval'] ?? null) ? $state['interval'] : 5;
        $polls = is_int($state['polls'] ?? null) ? $state['polls'] : 0;
        $now = $this->clock->now()->getTimestamp();

        if ($now >= (int) ($state['expires_at'] ?? 0)) {
            return $this->ended($handle, false, 'Nobody answered before the request expired.', $proofs);
        }
        if ($now < (int) ($state['next_at'] ?? 0)) {
            return false;
        }

        try {
            $answer = $this->endpoint->post('token_endpoint', $form, $clientId, $secret);
        } catch (ForgeException $exception) {
            return $this->ended($handle, false, $exception->getMessage(), $proofs);
        }
        ++$polls;
        $error = $answer['body']['error'] ?? null;
        if ($error === 'authorization_pending' || $error === 'slow_down') {
            $interval += $error === 'slow_down' ? 5 : 0;
            $this->waiting->start($handle, [...$state, 'interval' => $interval, 'next_at' => $now + $interval, 'polls' => $polls]);

            return false;
        }

        $proofs[] = [
            'label' => sprintf('Asked the token endpoint %d times', $polls),
            'what' => sprintf('"authorization_pending" until the user answered, every %d seconds', $interval),
            'payload' => null,
        ];
        $proofs[] = IssuedToken::proof(sprintf('Token endpoint → %d', $answer['status']), $answer['body']);
        $worked = $answer['status'] === 200 && is_string($answer['body']['access_token'] ?? null);

        return $this->ended($handle, $worked, $worked ? null : OAuthError::of($answer['body']), $proofs);
    }

    /**
     * @param list<array{label: string, what: string, payload: string|null}> $proofs
     */
    private function ended(string $handle, bool $worked, ?string $why, array $proofs): bool
    {
        $this->waiting->end($handle);
        $worked ? $this->runs->worked($handle, $proofs) : $this->runs->failed($handle, (string) $why, $proofs);

        return true;
    }
}
