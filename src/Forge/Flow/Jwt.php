<?php

declare(strict_types=1);

namespace App\Forge\Flow;

use App\Forge\ForgeException;
use App\Forge\Offer;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Core\Algorithm;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A128CBCHS256;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer as JweCompactSerializer;
use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer as JwsCompactSerializer;
use Psr\Clock\ClockInterface;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * What the clients of the forge sign, verify and open, in one place: a client of the forge signs its
 * assertions, its request objects and its proofs, and reads the documents the provider signed and
 * encrypted for it.
 *
 * The keys of the provider are read from the "jwks_uri" it announces and from nowhere else, and a
 * signature is verified against that set alone: a key a token names itself is never read (RFC 8725 §3.10).
 */
final readonly class Jwt
{
    /**
     * How long what a client signs for one request is good for, in seconds.
     */
    public const int LIFETIME = 60;

    /**
     * What a client of the forge can have a document encrypted to it with, and what the payload of such a
     * document can be encrypted with (RFC 7518 §4 and §5). It is one list, read twice: the manager below
     * is built from it, and the form of the forge offers what the provider announces that is in it
     * (TheForm), so a composition cannot ask for something this application would fail to open.
     *
     * The ECDH-ES algorithms the provider announces are not here: opening one needs the AES key wrap
     * package beside this library, which this demonstration does not install. Adding it is an issue of
     * its own, and until then the page offers RSA and says nothing about what it cannot do.
     */
    public const array OPENS = ['RSA-OAEP-256', 'RSA-OAEP'];

    public const array PAYLOADS = ['A256GCM', 'A128CBC-HS256'];

    private AlgorithmManager $signatures;

    private AlgorithmManager $encryptions;

    private JwsCompactSerializer $jws;

    private JweCompactSerializer $jwe;

    public function __construct(
        private HttpClientInterface $httpClient,
        private CacheInterface $cache,
        private ClockInterface $clock,
        private Offer $offer,
    ) {
        $this->signatures = new AlgorithmManager([new ES256(), new ES384(), new ES512(), new EdDSA(), new PS256(), new RS256(), new HS256()]);
        $this->encryptions = new AlgorithmManager([
            ...array_map(self::encryption(...), self::OPENS),
            ...array_map(self::encryption(...), self::PAYLOADS),
        ]);
        $this->jws = new JwsCompactSerializer();
        $this->jwe = new JweCompactSerializer();
    }

    public function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }

    /**
     * @param array<string, mixed> $claims
     * @param array<string, mixed> $header what goes beside the algorithm, the "typ" of RFC 8725 §3.11 and
     *                                     the key of a proof (RFC 9449 §4.2) being written by the caller
     *
     * @throws ForgeException when the key cannot sign that
     */
    public function sign(array $claims, JWK $key, string $algorithm, array $header = []): string
    {
        try {
            return $this->jws->serialize(
                (new JWSBuilder($this->signatures))
                    ->create()
                    ->withPayload((string) json_encode($claims, \JSON_THROW_ON_ERROR))
                    ->addSignature($key, array_filter([
                        'alg' => $algorithm,
                        'kid' => $key->has('kid') ? $key->get('kid') : null,
                        ...$header,
                    ], static fn (mixed $value): bool => $value !== null))
                    ->build()
            );
        } catch (\Throwable $exception) {
            throw new ForgeException(sprintf('This client cannot sign with %s: %s', $algorithm, $exception->getMessage()), previous: $exception);
        }
    }

    /**
     * The claims of a token the provider signed, verified against the keys it publishes.
     *
     * @return array<string, mixed>
     *
     * @throws ForgeException when it is not a JWS, does not verify, or holds no JSON object
     */
    public function verify(string $token): array
    {
        try {
            $jws = $this->jws->unserialize($token);
        } catch (\Throwable $exception) {
            throw new ForgeException('The provider sent something that is not a compact JWS.', previous: $exception);
        }
        $verifier = new JWSVerifier($this->signatures);
        if (! $verifier->verifyWithKeySet($jws, $this->providerKeys(), 0)) {
            throw new ForgeException('The signature of the provider does not verify against its JWK Set.');
        }
        $claims = json_decode((string) $jws->getPayload(), true);
        if (! is_array($claims)) {
            throw new ForgeException('What the provider signed is not a JSON object.');
        }

        /** @var array<string, mixed> $claims */
        return $claims;
    }

    /**
     * What the provider encrypted to a key this client publishes, opened with its private half.
     *
     * @return array{string, string} what it held, and how it was encrypted
     *
     * @throws ForgeException when it is not a JWE or cannot be opened
     */
    public function decrypt(string $token, JWK $key): array
    {
        try {
            $jwe = $this->jwe->unserialize($token);
        } catch (\Throwable $exception) {
            throw new ForgeException('The provider sent something that is not a compact JWE.', previous: $exception);
        }
        if (! (new JWEDecrypter($this->encryptions))->decryptUsingKey($jwe, $key, 0)) {
            throw new ForgeException('What the provider encrypted cannot be opened with the key this client publishes.');
        }
        $header = $jwe->getSharedProtectedHeader();

        return [
            (string) $jwe->getPayload(),
            sprintf('%s / %s', $header['alg'] ?? '?', $header['enc'] ?? '?'),
        ];
    }

    /**
     * The algorithm a token says it was made with, read from its header for the page to print. Nothing is
     * decided on it: what a signature verifies against is the key set of the provider.
     *
     * @return array<string, mixed>
     */
    public function header(string $token): array
    {
        $header = json_decode((string) base64_decode(strtr(explode('.', $token)[0] ?? '', '-_', '+/'), true), true);

        return is_array($header) ? $header : [];
    }

    /**
     * Whether a compact token is a JWE, which has five parts where a JWS has three (RFC 7516 §3.1).
     */
    public function isEncrypted(string $token): bool
    {
        return substr_count($token, '.') === 4;
    }

    /**
     * The algorithm of that name, among the ones this demonstration installs.
     *
     * @throws ForgeException when nothing here is that algorithm, which means OPENS or PAYLOADS names
     *                        something the lock file does not hold
     */
    private static function encryption(string $name): Algorithm
    {
        return match ($name) {
            'RSA-OAEP-256' => new RSAOAEP256(),
            'RSA-OAEP' => new RSAOAEP(),
            'A256GCM' => new A256GCM(),
            'A128CBC-HS256' => new A128CBCHS256(),
            default => throw new ForgeException(sprintf('This demonstration installs no "%s".', $name)),
        };
    }

    private function providerKeys(): JWKSet
    {
        /** @var array<string, mixed> $keys */
        $keys = $this->cache->get('forge.jwks.' . hash('xxh128', $this->offer->issuer()), function (ItemInterface $item): array {
            $item->expiresAfter(3600);
            $response = $this->httpClient->request('GET', $this->offer->endpoint('jwks_uri'), [
                'max_redirects' => 0,
            ]);
            $values = json_decode($response->getContent(false), true);

            return is_array($values) ? $values : [];
        });

        return JWKSet::createFromKeyData($keys);
    }
}
