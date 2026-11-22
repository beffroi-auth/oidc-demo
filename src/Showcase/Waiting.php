<?php

declare(strict_types=1);

namespace App\Showcase;

use Symfony\Component\HttpFoundation\RequestStack;

/**
 * The runs of this browser that wait on the user, by handle: what the provider handed out to wait with
 * (a device code, an authentication request identifier) and what the panel shows meanwhile.
 */
final readonly class Waiting
{
    private const string KEY = 'showcase.waiting';

    public function __construct(
        private RequestStack $requests,
    ) {
    }

    /**
     * @param array<string, mixed> $state
     */
    public function start(string $handle, array $state): void
    {
        $all = $this->all();
        $all[$handle] = $state;
        $this->write($all);
    }

    /**
     * @return array<string, mixed>|null
     */
    public function of(string $handle): ?array
    {
        return $this->all()[$handle] ?? null;
    }

    public function end(string $handle): void
    {
        $all = $this->all();
        unset($all[$handle]);
        $this->write($all);
    }

    /**
     * @return array<string, array<string, mixed>>
     */
    private function all(): array
    {
        $request = $this->requests->getCurrentRequest();
        $all = $request !== null && $request->hasSession() ? $request->getSession()->get(self::KEY, []) : [];

        /** @var array<string, array<string, mixed>> */
        return is_array($all) ? $all : [];
    }

    /**
     * @param array<string, array<string, mixed>> $all
     */
    private function write(array $all): void
    {
        $request = $this->requests->getCurrentRequest();
        if ($request !== null && $request->hasSession()) {
            $request->getSession()->set(self::KEY, $all);
        }
    }
}
