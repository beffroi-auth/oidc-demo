<?php

declare(strict_types=1);

namespace App\Showcase\Api;

use App\Api\AddressedHereOrDescribed;
use Psr\Clock\ClockInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

/**
 * Writes each call of the API of /api/v1 into the journal once it is answered, the documentation and the
 * vocabulary the answers point at left out.
 */
#[AsEventListener]
final readonly class RecordsTheApiCalls
{
    public function __construct(
        private ApiJournal $journal,
        private ClockInterface $clock,
    ) {
    }

    public function __invoke(ResponseEvent $event): void
    {
        $request = $event->getRequest();
        if (! $event->isMainRequest() || preg_match('#^/api/v1/(account|invoices)#', $request->getPathInfo()) !== 1) {
            return;
        }

        $checked = $request->attributes->get(AddressedHereOrDescribed::CHECKED);
        $claims = is_array($checked) && is_array($checked['claims'] ?? null) ? $checked['claims'] : [];
        $challenge = $event->getResponse()->headers->get('WWW-Authenticate') ?? '';

        $this->journal->record([
            'at' => $this->clock->now()->getTimestamp(),
            'call' => sprintf('%s %s', $request->getMethod(), $request->getPathInfo()),
            'status' => $event->getResponse()->getStatusCode(),
            'how' => is_array($checked) && is_string($checked['how'] ?? null) ? $checked['how'] : null,
            'client_id' => is_string($claims['client_id'] ?? null) ? $claims['client_id'] : null,
            'sub' => is_string($claims['sub'] ?? null) ? $claims['sub'] : null,
            'scope' => is_string($claims['scope'] ?? null) ? $claims['scope'] : null,
            'error' => preg_match('/error="([^"]+)"/', $challenge, $error) === 1 ? $error[1] : null,
        ]);
    }
}
