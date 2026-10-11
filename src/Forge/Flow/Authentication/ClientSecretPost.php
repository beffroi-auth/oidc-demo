<?php

declare(strict_types=1);

namespace App\Forge\Flow\Authentication;

use App\Forge\BuiltClient;
use App\Forge\ForgeException;

/**
 * RFC 6749 §2.3.1: the same secret, in the body of the request rather than in a header. The specification
 * prefers the header and allows this one, which is what a client whose stack cannot set a header uses.
 */
final readonly class ClientSecretPost implements HoldsASharedSecretInterface
{
    public function name(): string
    {
        return 'client_secret_post';
    }

    public function describe(): string
    {
        return 'client_secret_post: the identifier and the secret in the body of the request (RFC 6749 §2.3.1)';
    }

    public function apply(BuiltClient $client, array $options): array
    {
        /** @var array<string, mixed> $body */
        $body = is_array($options['body'] ?? null) ? $options['body'] : [];
        $options['body'] = [
            ...$body,
            'client_id' => $client->clientId,
            'client_secret' => $client->clientSecret ?? throw new ForgeException(
                'This client authenticates with a secret and the provider issued none.',
            ),
        ];

        return $options;
    }
}
