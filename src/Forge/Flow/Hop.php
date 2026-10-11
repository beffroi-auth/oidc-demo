<?php

declare(strict_types=1);

namespace App\Forge\Flow;

/**
 * One thing that travelled, as the page of a built client prints it: where it went or came from, what it
 * was in one sentence, and what it actually was when that is something a reader can be shown, a request
 * object, a signed response, the answer of the token endpoint.
 *
 * A hop is recorded by the step that made it, so the page shows the flow that happened rather than the
 * flow the composition asked for.
 */
final readonly class Hop
{
    public function __construct(
        public string $label,
        public string $what,
        public ?string $payload = null,
    ) {
    }

    /**
     * @return array{label: string, what: string, payload: string|null}
     */
    public function toArray(): array
    {
        return [
            'label' => $this->label,
            'what' => $this->what,
            'payload' => $this->payload,
        ];
    }
}
