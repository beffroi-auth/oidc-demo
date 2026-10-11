<?php

declare(strict_types=1);

namespace App\Forge\Flow\Authentication;

use App\Forge\BuiltClient;

/**
 * RFC 6749 §2.1: a public client, which authenticates in no way at all and names itself. What ties the
 * code to whoever asked for it is PKCE, mandatory here for every client and not only for this one
 * (decision 0006, RFC 7636 §4.3).
 */
final readonly class NoClientAuthentication implements ClientAuthenticationInterface
{
    public function name(): string
    {
        return 'none';
    }

    public function describe(): string
    {
        return 'none: a public client, which holds no credential and is tied to its request by PKCE S256 alone (RFC 7636)';
    }

    public function apply(BuiltClient $client, array $options): array
    {
        /** @var array<string, mixed> $body */
        $body = is_array($options['body'] ?? null) ? $options['body'] : [];
        $options['body'] = [
            ...$body,
            'client_id' => $client->clientId,
        ];

        return $options;
    }
}
