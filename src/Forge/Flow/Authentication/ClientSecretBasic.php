<?php

declare(strict_types=1);

namespace App\Forge\Flow\Authentication;

use App\Forge\BuiltClient;
use App\Forge\ForgeException;

/**
 * RFC 6749 §2.3.1: the identifier and the secret in the Authorization header of the request, which is the
 * method RFC 7591 §2 gives a client that registers none.
 */
final readonly class ClientSecretBasic implements HoldsASharedSecretInterface
{
    public function name(): string
    {
        return 'client_secret_basic';
    }

    public function describe(): string
    {
        return 'client_secret_basic: the identifier and the secret in the Authorization header (RFC 6749 §2.3.1)';
    }

    public function apply(BuiltClient $client, array $options): array
    {
        $options['auth_basic'] = [$client->clientId, $client->clientSecret ?? throw new ForgeException(
            'This client authenticates with a secret and the provider issued none.',
        )];

        return $options;
    }
}
