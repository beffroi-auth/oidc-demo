<?php

declare(strict_types=1);

namespace App\Forge\Flow\Authentication;

use App\Forge\BuiltClient;

/**
 * RFC 7523 §2.2: the client signs an assertion with the key it published in its registration and shares
 * no secret at all. The provider issues it none, so there is nothing to rotate, nothing to leak out of a
 * configuration file, and nothing of the client in a store of the provider but a public key.
 */
final readonly class PrivateKeyJwt implements PublishesAKeyInterface
{
    public function __construct(
        private ClientAssertion $assertion,
    ) {
    }

    public function name(): string
    {
        return 'private_key_jwt';
    }

    public function describe(): string
    {
        return 'private_key_jwt: an assertion signed with the key this client published, and no secret anywhere (RFC 7523 §2.2)';
    }

    public function apply(BuiltClient $client, array $options): array
    {
        /** @var array<string, mixed> $body */
        $body = is_array($options['body'] ?? null) ? $options['body'] : [];
        $options['body'] = [
            ...$body,
            'client_id' => $client->clientId,
            ...$this->assertion->parameters(
                $client,
                $client->material->signingJwk(),
                $client->material->signingAlgorithm ?? 'ES256',
            ),
        ];

        return $options;
    }
}
