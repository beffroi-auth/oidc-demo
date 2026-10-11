<?php

declare(strict_types=1);

namespace App\Forge;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\X509\Certificate\Certificate;

/**
 * What a composition needs of the forge before it can be registered, drawn when the client is built and
 * never committed: the key it signs with (RFC 7523 §2.2 and RFC 9101 §4 ask for the same one), a key per
 * algorithm the provider is to encrypt a document with (OIDC Core §3.1.3.7, §5.3.2, JARM §3), and the
 * certificate of a client that presents one (RFC 8705 §2).
 *
 * The client publishes the public half of all of it in the "jwks" of its registration (RFC 7591 §2), and
 * the private halves stay here, in the store of the built clients. A client of the forge lives as long as
 * the provider keeps it, which is a day of use at most (decision 0009), so none of this is kept for
 * longer than the client it belongs to.
 */
final readonly class Material
{
    /**
     * What the drawn key is for, as RFC 7517 §4.2 writes it: a signature or an encryption, never both.
     */
    private const string SIGNATURE = 'sig';

    private const string ENCRYPTION = 'enc';

    /**
     * @param array<string, string> $encryptionKeys the private half of each one, as JSON, by the algorithm it is for
     */
    public function __construct(
        public ?string $signingKey = null,
        public ?string $signingAlgorithm = null,
        public array $encryptionKeys = [],
        public ?string $certificate = null,
        public ?string $certificateKey = null,
        public ?string $subjectName = null,
    ) {
    }

    /**
     * Everything the composition asks for, drawn once. The signing algorithm is the one the client
     * registered for its request objects when it registered one, and ES256 otherwise: a client signs its
     * assertions and its requests with one key, so it names one algorithm.
     *
     * @throws ForgeException when a key of that algorithm cannot be drawn
     */
    public static function drawnFor(Composition $composition, bool $signs, bool $presentsACertificate, string $handle): self
    {
        $algorithm = $composition->request->requestObjectSigningAlgorithm ?? 'ES256';
        $signingKey = $signs || $composition->needsASigningKey()
            ? self::key($algorithm, self::SIGNATURE)
            : null;

        $encryptionKeys = [];
        foreach ($composition->documents->keyEncryptionAlgorithms() as $encryption) {
            $encryptionKeys[$encryption] = self::json(self::key($encryption, self::ENCRYPTION));
        }

        [$certificate, $certificateKey, $subjectName] = $presentsACertificate
            ? self::certificate($handle)
            : [null, null, null];

        return new self(
            $signingKey === null ? null : self::json($signingKey),
            $signingKey === null ? null : $algorithm,
            $encryptionKeys,
            $certificate,
            $certificateKey,
            $subjectName,
        );
    }

    /**
     * The key set this client publishes (RFC 7591 §2 "jwks"), public halves only, each key naming the
     * algorithm and the use it was drawn for so that the provider never has to guess which is which. The
     * certificate of a client that authenticates by one goes in the same set, in the "x5c" of its key
     * (RFC 7517 §4.7), which is where RFC 8705 §2.2 reads it.
     *
     * @return array{keys: list<array<string, mixed>>}|null
     */
    public function publishedKeys(): ?array
    {
        $keys = [];
        if ($this->signingKey !== null) {
            $keys[] = $this->jwk($this->signingKey)->toPublic()->all();
        }
        foreach ($this->encryptionKeys as $key) {
            $keys[] = $this->jwk($key)->toPublic()->all();
        }
        if ($this->certificate !== null) {
            $keys[] = $this->certificateKeySet();
        }

        return $keys === [] ? null : ['keys' => $keys];
    }

    public function signs(): bool
    {
        return $this->signingKey !== null;
    }

    public function signingJwk(): JWK
    {
        return $this->jwk($this->signingKey ?? throw new ForgeException('This client holds no signing key.'));
    }

    /**
     * The key a document encrypted with that algorithm is opened with.
     *
     * @throws ForgeException when the client published none for it
     */
    public function encryptionJwk(string $algorithm): JWK
    {
        return $this->jwk($this->encryptionKeys[$algorithm] ?? throw new ForgeException(sprintf(
            'This client holds no key for "%s", which is what the provider encrypted a document with.',
            $algorithm,
        )));
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'signing_key' => $this->signingKey,
            'signing_algorithm' => $this->signingAlgorithm,
            'encryption_keys' => $this->encryptionKeys,
            'certificate' => $this->certificate,
            'certificate_key' => $this->certificateKey,
            'subject_name' => $this->subjectName,
        ];
    }

    /**
     * @param array<string, mixed> $values
     */
    public static function fromArray(array $values): self
    {
        /** @var array<string, string> $encryptionKeys */
        $encryptionKeys = is_array($values['encryption_keys'] ?? null) ? $values['encryption_keys'] : [];

        return new self(
            is_string($values['signing_key'] ?? null) ? $values['signing_key'] : null,
            is_string($values['signing_algorithm'] ?? null) ? $values['signing_algorithm'] : null,
            $encryptionKeys,
            is_string($values['certificate'] ?? null) ? $values['certificate'] : null,
            is_string($values['certificate_key'] ?? null) ? $values['certificate_key'] : null,
            is_string($values['subject_name'] ?? null) ? $values['subject_name'] : null,
        );
    }

    /**
     * A key of the kind the algorithm asks for: the curve of an elliptic one, the size of an RSA one, the
     * curve of an octet key pair. An algorithm nothing here draws a key for is refused rather than served
     * with a key of another kind, which the provider would read and fail on.
     *
     * @throws ForgeException when no key of that algorithm is drawn here
     */
    private static function key(string $algorithm, string $use): JWK
    {
        $parameters = [
            'alg' => $algorithm,
            'use' => $use,
        ];

        return match ($algorithm) {
            'ES256' => JWKFactory::createECKey('P-256', $parameters),
            'ES384' => JWKFactory::createECKey('P-384', $parameters),
            'ES512' => JWKFactory::createECKey('P-521', $parameters),
            'EdDSA' => JWKFactory::createOKPKey('Ed25519', $parameters),
            'RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'RSA-OAEP-256', 'RSA-OAEP', 'RSA-OAEP-384', 'RSA-OAEP-512' => JWKFactory::createRSAKey(2048, $parameters),
            default => throw new ForgeException(sprintf('The forge draws no key for "%s".', $algorithm)),
        };
    }

    /**
     * RFC 8705 §2: the certificate a client of the forge presents, self-signed and good for a day, which
     * is longer than the provider keeps a client nobody used. Its subject names the built client, so a
     * certificate presented by another one is another subject whatever else it says.
     *
     * @return array{string, string, string}
     *
     * @throws ForgeException when the certificate cannot be drawn
     */
    private static function certificate(string $handle): array
    {
        $name = [
            'commonName' => sprintf('forge-%s', $handle),
            'organizationName' => 'The forge of the demonstration',
        ];
        $key = openssl_pkey_new([
            'private_key_type' => \OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);
        $request = $key === false ? false : openssl_csr_new($name, $key, ['digest_alg' => 'sha256']);
        $certificate = $request === false ? false : openssl_csr_sign($request, null, $key, 1, ['digest_alg' => 'sha256']);
        if ($key === false || $certificate === false) {
            throw new ForgeException('The forge could not draw a client certificate: ' . (openssl_error_string() ?: 'openssl says nothing'));
        }

        openssl_x509_export($certificate, $pem);
        openssl_pkey_export($key, $privateKey);

        return [$pem, $privateKey, self::distinguishedName($pem)];
    }

    /**
     * RFC 8705 §2.1.2 and RFC 4514: the subject of that certificate written the way the provider writes
     * the one it reads off the connection, which is what it compares a registered name with, byte for
     * byte. It is read from the structure with the same library the provider reads it with
     * (pki-framework), never taken apart with a regular expression.
     *
     * @throws ForgeException when the certificate cannot be read back
     */
    private static function distinguishedName(string $pem): string
    {
        try {
            return Certificate::fromPEM(PEM::fromString($pem))->tbsCertificate()->subject()->toString();
        } catch (\Throwable $exception) {
            throw new ForgeException('The certificate the forge drew cannot be read back.', previous: $exception);
        }
    }

    /**
     * RFC 7517 §4.7 and RFC 8705 §2.2: the certificate as a key of the published set, the chain carrying
     * it in the form a certificate travels in a key set, which is its DER in base64 and not its PEM.
     *
     * @return array<string, mixed>
     */
    private function certificateKeySet(): array
    {
        $certificate = (string) $this->certificate;
        $key = JWKFactory::createFromCertificate($certificate, ['use' => self::SIGNATURE]);
        $der = preg_replace('/-----[A-Z ]+-----|\s+/', '', $certificate) ?? '';

        return [
            ...$key->toPublic()->all(),
            'x5c' => [$der],
        ];
    }

    private function jwk(string $json): JWK
    {
        $values = json_decode($json, true);
        if (! is_array($values)) {
            throw new ForgeException('A key of this built client cannot be read back.');
        }

        /** @var array<string, mixed> $values */
        return new JWK($values);
    }

    private static function json(JWK $key): string
    {
        return (string) json_encode($key->all(), \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES);
    }
}
