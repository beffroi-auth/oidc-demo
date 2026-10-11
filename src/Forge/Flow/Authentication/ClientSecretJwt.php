<?php

declare(strict_types=1);

namespace App\Forge\Flow\Authentication;

use App\Forge\BuiltClient;
use App\Forge\ForgeException;
use Jose\Component\KeyManagement\JWKFactory;

/**
 * RFC 7523 §2.2 with a shared secret: the client signs the same assertion, with HS256 over the secret the
 * provider issued. The secret never travels, which is what tells this method from "client_secret_post",
 * and the provider still holds one, which is what tells it from "private_key_jwt".
 */
final readonly class ClientSecretJwt implements HoldsASharedSecretInterface
{
    private const string ALGORITHM = 'HS256';

    public function __construct(
        private ClientAssertion $assertion,
    ) {
    }

    public function name(): string
    {
        return 'client_secret_jwt';
    }

    public function describe(): string
    {
        return 'client_secret_jwt: an assertion signed with HS256 over the shared secret, which never travels (RFC 7523 §2.2)';
    }

    public function apply(BuiltClient $client, array $options): array
    {
        $secret = $client->clientSecret ?? throw new ForgeException('This client signs with a secret and the provider issued none.');
        /** @var array<string, mixed> $body */
        $body = is_array($options['body'] ?? null) ? $options['body'] : [];
        $options['body'] = [
            ...$body,
            'client_id' => $client->clientId,
            ...$this->assertion->parameters(
                $client,
                JWKFactory::createFromSecret($secret, ['alg' => self::ALGORITHM, 'use' => 'sig']),
                self::ALGORITHM,
            ),
        ];

        return $options;
    }
}
