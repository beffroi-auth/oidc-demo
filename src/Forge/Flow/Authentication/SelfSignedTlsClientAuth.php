<?php

declare(strict_types=1);

namespace App\Forge\Flow\Authentication;

use App\Forge\BuiltClient;

/**
 * RFC 8705 §2.2: the client presents a certificate it signed itself, and the provider recognises it
 * because the client published it in its key set. Nothing names an authority: what is compared is the
 * certificate of the connection against the one of the registration.
 */
final readonly class SelfSignedTlsClientAuth implements PresentsACertificateInterface
{
    public function __construct(
        private CertificateFiles $files,
    ) {
    }

    public function name(): string
    {
        return 'self_signed_tls_client_auth';
    }

    public function describe(): string
    {
        return 'self_signed_tls_client_auth: the certificate of the connection, compared with the one this client published in its key set (RFC 8705 §2.2)';
    }

    public function registration(?string $subjectName): array
    {
        return [];
    }

    public function apply(BuiltClient $client, array $options): array
    {
        /** @var array<string, mixed> $body */
        $body = is_array($options['body'] ?? null) ? $options['body'] : [];

        // RFC 8705 §2: the certificate authenticates the client and the body names it, there being
        // nothing else in the request that does
        return [
            ...$options,
            'body' => [
                ...$body,
                'client_id' => $client->clientId,
            ],
            ...$this->transport($client),
        ];
    }

    public function transport(BuiltClient $client): array
    {
        [$certificate, $key] = $this->files->of($client);

        return [
            'local_cert' => $certificate,
            'local_pk' => $key,
        ];
    }
}
