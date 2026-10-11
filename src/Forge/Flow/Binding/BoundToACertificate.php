<?php

declare(strict_types=1);

namespace App\Forge\Flow\Binding;

use App\Forge\BuiltClient;
use App\Forge\Flow\Authentication\CertificateFiles;
use App\Forge\ForgeException;
use SpomkyLabs\Pki\CryptoEncoding\PEM;

/**
 * RFC 8705 §3: the token is bound to the certificate the client presents, which the provider names in
 * "cnf.x5t#S256". The client proves nothing beside the connection it opened, so the binding costs it one
 * certificate and no signature at all, and the provider refuses the token to anybody who presents
 * another.
 */
final readonly class BoundToACertificate implements TokenBindingInterface
{
    public function __construct(
        private CertificateFiles $files,
    ) {
    }

    public function name(): string
    {
        return 'mtls';
    }

    public function describe(): string
    {
        return 'mtls: the token is bound to the certificate of the connection, which the provider names in "cnf.x5t#S256" (RFC 8705 §3)';
    }

    public function remember(?string $algorithm): array
    {
        return [];
    }

    public function needsTheCertificateEndpoints(): bool
    {
        return true;
    }

    public function scheme(): string
    {
        return 'Bearer';
    }

    public function apply(string $method, string $url, array $options, array $remembered, BuiltClient $client, ?string $accessToken = null): array
    {
        [$certificate, $key] = $this->files->of($client);

        return [
            ...$options,
            'local_cert' => $certificate,
            'local_pk' => $key,
        ];
    }

    /**
     * RFC 8705 §3.1: the certificate as the provider names it, the digest of its DER in base64url.
     */
    public function confirmation(array $remembered, BuiltClient $client): ?string
    {
        $certificate = $client->material->certificate;
        if ($certificate === null) {
            throw new ForgeException('This client binds its tokens to a certificate and holds none.');
        }

        return rtrim(strtr(base64_encode(hash('sha256', PEM::fromString($certificate)->data(), true)), '+/', '-_'), '=');
    }
}
