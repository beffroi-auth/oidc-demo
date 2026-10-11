<?php

declare(strict_types=1);

namespace App\Forge\Flow;

/**
 * A login that has begun: where the browser is being sent, and what the client has to remember until the
 * answer comes back (OIDC Core §3.1.2.1, RFC 7636 §4.1), the hops already made among it so that the page
 * can show the request even when the answer never arrives.
 */
final readonly class StartedFlow
{
    /**
     * @param array<string, mixed> $remembered
     */
    public function __construct(
        public string $url,
        public array $remembered,
    ) {
    }
}
