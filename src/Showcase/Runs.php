<?php

declare(strict_types=1);

namespace App\Showcase;

use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * What the last run of each client did in this browser, kept in its session: the tree lights a square
 * from it and the panel shows its proof. A run left unfinished at the provider leaves the one before it.
 */
final readonly class Runs
{
    private const string KEY = 'showcase.runs';

    public function __construct(
        private RequestStack $requests,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @param list<array{label: string, what: string, payload: string|null}> $proofs
     */
    public function worked(string $handle, array $proofs): void
    {
        $this->keep($handle, [
            'worked' => true,
            'at' => $this->clock->now()->getTimestamp(),
            'why' => null,
            'proofs' => $proofs,
        ]);
    }

    /**
     * @param list<array{label: string, what: string, payload: string|null}> $proofs what travelled before it failed
     */
    public function failed(string $handle, string $why, array $proofs = []): void
    {
        $this->keep($handle, [
            'worked' => false,
            'at' => $this->clock->now()->getTimestamp(),
            'why' => $why,
            'proofs' => $proofs,
        ]);
    }

    public function forget(string $handle): void
    {
        $request = $this->requests->getCurrentRequest();
        if ($request === null || ! $request->hasSession()) {
            return;
        }
        $runs = $this->all();
        unset($runs[$handle]);
        $request->getSession()->set(self::KEY, $runs);
    }

    /**
     * @return array{worked: bool, at: int, why: string|null, proofs: list<array{label: string, what: string, payload: string|null}>}|null
     */
    public function of(string $handle): ?array
    {
        return $this->all()[$handle] ?? null;
    }

    /**
     * @return array<string, array{worked: bool, at: int, why: string|null, proofs: list<array{label: string, what: string, payload: string|null}>}>
     */
    private function all(): array
    {
        $request = $this->requests->getCurrentRequest();
        if ($request === null || ! $request->hasSession()) {
            return [];
        }
        $runs = $request->getSession()->get(self::KEY, []);

        /** @var array<string, array{worked: bool, at: int, why: string|null, proofs: list<array{label: string, what: string, payload: string|null}>}> $runs */
        return is_array($runs) ? $runs : [];
    }

    /**
     * @param array{worked: bool, at: int, why: string|null, proofs: list<array{label: string, what: string, payload: string|null}>} $run
     */
    private function keep(string $handle, array $run): void
    {
        $request = $this->requests->getCurrentRequest();
        if ($request === null || ! $request->hasSession()) {
            return;
        }
        $runs = $this->all();
        $runs[$handle] = $run;
        $request->getSession()->set(self::KEY, $runs);
    }
}
