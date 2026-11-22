<?php

declare(strict_types=1);

namespace App\Showcase\Grant;

use App\Api\AddressedHereOrDescribed;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * Whether the API of /api/v1 would let a token in, asked of the very handler its firewall uses, so that a
 * token a client obtained without any browser is shown to be good where it is meant to be spent.
 */
final readonly class TheApiAccepts
{
    public function __construct(
        private AddressedHereOrDescribed $handler,
    ) {
    }

    /**
     * @return array{label: string, what: string, payload: string|null, ok: bool}
     */
    public function proof(string $accessToken): array
    {
        try {
            $claims = $this->handler->getUserBadgeFrom($accessToken)->getAttributes() ?? [];
        } catch (AuthenticationException $exception) {
            return [
                'label' => 'The API refuses it',
                'what' => $exception->getMessageKey(),
                'payload' => null,
                'ok' => false,
            ];
        }

        return [
            'label' => 'The API accepts it',
            'what' => sprintf(
                'sub %s, scope %s, as /api/v1 verifies it',
                IssuedToken::text($claims['sub'] ?? null),
                IssuedToken::text($claims['scope'] ?? null),
            ),
            'payload' => null,
            'ok' => true,
        ];
    }
}
