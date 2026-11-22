<?php

declare(strict_types=1);

namespace App\Showcase\Api;

/**
 * The calls of the journal a client made, as the proof of a panel: one step per call, ticked when the API
 * answered it, and the run judged on the last one.
 */
final class CallsAsProof
{
    /**
     * @param list<array{at: int, call: string, status: int, how: string|null, client_id: string|null, sub: string|null, scope: string|null, error: string|null}> $calls
     *
     * @return array{worked: bool, at: int, why: string|null, proofs: list<array{label: string, what: string, payload: string|null, ok: bool}>}|null
     */
    public static function of(array $calls): ?array
    {
        if ($calls === []) {
            return null;
        }

        $proofs = [];
        foreach ($calls as $call) {
            $proofs[] = [
                'label' => sprintf('%s → %d', $call['call'], $call['status']),
                'what' => implode(', ', array_filter([
                    $call['how'],
                    $call['scope'] === null ? null : 'scope ' . $call['scope'],
                    $call['error'],
                    date('H:i:s', $call['at']),
                ])),
                'payload' => null,
                'ok' => $call['status'] < 400 || $call['error'] === 'insufficient_scope',
            ];
        }

        return [
            'worked' => array_any($calls, static fn (array $call): bool => $call['status'] < 400),
            'at' => $calls[0]['at'],
            'why' => null,
            'proofs' => $proofs,
        ];
    }
}
