<?php

declare(strict_types=1);

namespace App\Forge\Composed;

use App\Forge\Chosen;
use App\Forge\Offer;

/**
 * How the client proves it is itself (RFC 6749 §2.3, RFC 7523 §2.2, RFC 8705 §2): one name among those
 * the provider announces, and nothing else.
 *
 * What that name does on the wire, and what it needs of the forge, which is a secret the provider issues,
 * a key the client publishes or a certificate it presents, belongs to the class of that method
 * (App\Forge\Flow\Authentication): this object says what was composed and never how it is sent.
 */
final readonly class Credentials
{
    public function __construct(
        public string $method,
    ) {
    }

    /**
     * @param array<string, mixed> $input
     *
     * @throws \App\Forge\ForgeException when the provider authenticates no client that way
     */
    public static function read(array $input, Offer $offer): self
    {
        return new self(Chosen::one(
            $input['token_endpoint_auth_method'] ?? null,
            $offer->names('token_endpoint_auth_methods_supported'),
            'token_endpoint_auth_method',
        ));
    }

    /**
     * @return array<string, mixed>
     */
    public function registration(): array
    {
        return [
            'token_endpoint_auth_method' => $this->method,
        ];
    }
}
