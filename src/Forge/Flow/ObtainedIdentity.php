<?php

declare(strict_types=1);

namespace App\Forge\Flow;

/**
 * What a client of the forge ends a login with: the claims it knows the user by, the tokens it holds, and
 * every hop of the flow it played, which is what its page exists to show.
 */
final readonly class ObtainedIdentity
{
    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $tokens
     * @param list<array{label: string, what: string, payload: string|null}> $hops
     */
    public function __construct(
        public string $subject,
        public array $claims,
        public array $tokens,
        public array $hops,
    ) {
    }
}
