<?php

declare(strict_types=1);

namespace App\Forge\Flow\Authentication;

use App\Forge\BuiltClient;

/**
 * RFC 8705 §2.1: the client presents a certificate and the provider recognises the name in it, which the
 * client registered. The provider trusts the edge for the chain and judges the name alone, so what the
 * registration carries is the subject as RFC 4514 writes it (§2.1.2).
 */
final readonly class TlsClientAuth implements PresentsACertificateInterface
{
    public function __construct(
        private CertificateFiles $files,
    ) {
    }

    public function name(): string
    {
        return 'tls_client_auth';
    }

    public function describe(): string
    {
        return 'tls_client_auth: the certificate of the connection, whose subject is the name this client registered (RFC 8705 §2.1)';
    }

    public function registration(?string $subjectName): array
    {
        return $subjectName === null ? [] : [
            'tls_client_auth_subject_dn' => $subjectName,
        ];
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
