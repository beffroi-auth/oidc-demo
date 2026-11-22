<?php

declare(strict_types=1);

namespace App\Showcase;

/**
 * What the panel of a feature shows, whichever client faces it.
 */
final readonly class ClientView
{
    /**
     * @param list<array{text: string, hl: bool}> $lines the configuration, one line each, the lines that make the feature highlighted
     * @param array{worked: bool, at: int, why: string|null, proofs: list<array{label: string, what: string, payload: string|null, ok?: bool}>}|null $run the last run in this browser, a step without "ok" being one that held
     * @param array{says: string, code: string|null, link: string|null, linkLabel: string, interval: int}|null $waiting a run waiting on the user, what they are to do meanwhile
     */
    public function __construct(
        public string $client,
        public ?string $clientId,
        public string $source,
        public array $lines,
        public ?array $run,
        public bool $offered = true,
        public ?string $notice = null,
        public ?string $page = null,
        public string $pageLabel = 'Everything it holds',
        public string $hint = 'Run it: every step it takes is ticked here.',
        public ?array $waiting = null,
    ) {
    }
}
