<?php

declare(strict_types=1);

namespace App\Forge\Flow\Binding;

use App\Forge\BuiltClient;

/**
 * RFC 6750 §1.2: a bearer token, which is spent by whoever holds it. It is what every client got before
 * there was anything else, and what a client still gets when it asks for nothing more.
 */
final readonly class NoBinding implements TokenBindingInterface
{
    public function name(): string
    {
        return 'none';
    }

    public function describe(): string
    {
        return 'none: a bearer token, which whoever holds it can spend (RFC 6750 §1.2)';
    }

    public function remember(?string $algorithm): array
    {
        return [];
    }

    public function needsTheCertificateEndpoints(): bool
    {
        return false;
    }

    public function scheme(): string
    {
        return 'Bearer';
    }

    public function apply(string $method, string $url, array $options, array $remembered, BuiltClient $client, ?string $accessToken = null): array
    {
        return $options;
    }

    public function confirmation(array $remembered, BuiltClient $client): ?string
    {
        return null;
    }
}
