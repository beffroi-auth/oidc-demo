<?php

declare(strict_types=1);

namespace App\Security\Fapi;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\JWKSet;
use Jose\Component\Encryption\Algorithm\ContentEncryption\A256GCM;
use Jose\Component\Encryption\Algorithm\KeyEncryption\RSAOAEP256;
use Jose\Component\Encryption\JWEDecrypter;
use Jose\Component\Encryption\Serializer\CompactSerializer as JweCompactSerializer;
use Jose\Component\Signature\Algorithm\ES256;
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
 * The last rung of the ladder of demonstration clients (heidi#201): a client that asks the provider for
 * everything FAPI 2.0 has, and that Symfony's "oidc_login" cannot be today.
 *
 * It pushes its authorization request instead of putting it in the URL of a browser (RFC 9126), signs
 * what it pushes (RFC 9101), reads an authorization response that is a signed JWT (JARM), proves a key
 * at the token endpoint instead of sending a secret (RFC 7523), binds the access token it receives to a
 * key of its own (RFC 9449), and reads an ID token and a UserInfo answer the provider encrypted to the
 * key it publishes (OIDC Core §3.1.3.7 and §5.3.2).
 *
 * This is laboratory code, and it is not where the gap is fixed: `RP-04`, `RP-05`, `RP-06` and `RP-16`
 * of the Symfony status document are what is missing from `oidc_login`, and they stay open whatever this
 * class does here. Nothing of the provider is bent for it: everything below is what the provider serves
 * to any client registered the same way.
 */
final class FapiClient
{
    /**
     * OIDC Core §3.1.2.1 and RFC 9449 §4.2: what this client asks for, and the "typ" of each JWT it
     * signs, none of which may be taken for another (RFC 8725 §3.11).
     */
    public const SCOPE = 'openid profile email';

    private const REQUEST_OBJECT_TYPE = 'oauth-authz-req+jwt';

    private const PROOF_TYPE = 'dpop+jwt';

    private const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    /**
     * The lifetime of everything this client signs for one request, in seconds.
     */
    private const LIFETIME = 60;

    private readonly AlgorithmManager $signatureAlgorithms;

    private readonly AlgorithmManager $encryptionAlgorithms;

    private readonly JwsCompactSerializer $jws;

    private readonly JweCompactSerializer $jwe;

    public function __construct(
        private readonly HttpClientInterface $httpClient,
        private readonly CacheInterface $cache,
        private readonly ClockInterface $clock,
        private readonly string $providerUri,
        private readonly string $clientId,
        private readonly string $redirectUri,
        private readonly string $signatureKey,
        private readonly string $encryptionKey,
    ) {
        // the algorithms this client accepts of the provider, and the one it signs with: ES256 is what
        // the FAPI profile asks for, RS256 and PS256 are what the provider may sign its own documents
        // with when a client registers nothing else
        $this->signatureAlgorithms = new AlgorithmManager([new ES256(), new PS256(), new RS256()]);
        $this->encryptionAlgorithms = new AlgorithmManager([new RSAOAEP256(), new A256GCM()]);
        $this->jws = new JwsCompactSerializer();
        $this->jwe = new JweCompactSerializer();
    }

    public function clientId(): string
    {
        return $this->clientId;
    }

    public function redirectUri(): string
    {
        return $this->redirectUri;
    }

    public function isConfigured(): bool
    {
        return $this->signatureKey !== '' && $this->encryptionKey !== '';
    }

    /**
     * The document the provider publishes, read once and kept for an hour, as every other client of this
     * demonstration reads it.
     *
     * @return array<string, mixed>
     */
    public function metadata(): array
    {
        /** @var array<string, mixed> $metadata */
        $metadata = $this->cache->get('fapi.discovery.' . hash('xxh128', $this->providerUri), function (ItemInterface $item): array {
            $item->expiresAfter(3600);

            return $this->json('GET', $this->providerUri . '/.well-known/openid-configuration');
        });

        return $metadata;
    }

    /**
     * RFC 9126 §2: the authorization request is handed to the provider server to server, signed as a
     * request object (RFC 9101 §4), and what comes back is a URI the browser carries in place of it.
     * Nothing of the request travels through the browser, which is the whole point of the rung.
     *
     * @param array<string, string> $parameters the request, as an authorization request is written
     *
     * @return array{request_uri: string, expires_in: int, request_object: string}
     */
    public function pushAuthorizationRequest(array $parameters): array
    {
        $metadata = $this->metadata();
        $requestObject = $this->sign(
            [
                'iss' => $this->clientId,
                'aud' => $this->issuer(),
                'jti' => bin2hex(random_bytes(16)),
                'iat' => $this->now(),
                'nbf' => $this->now(),
                'exp' => $this->now() + self::LIFETIME,
                ...$parameters,
            ],
            self::REQUEST_OBJECT_TYPE,
        );

        $answer = $this->json('POST', $this->endpoint($metadata, 'pushed_authorization_request_endpoint'), [
            'body' => [
                'client_id' => $this->clientId,
                'request' => $requestObject,
                ...$this->clientAssertion(),
            ],
        ]);

        $requestUri = $answer['request_uri'] ?? null;
        if (! is_string($requestUri) || $requestUri === '') {
            throw new FapiException(sprintf(
                'The pushed authorization request of "%s" for "%s" was refused: %s',
                $this->clientId,
                $parameters['redirect_uri'] ?? '?',
                json_encode($answer),
            ));
        }

        return [
            'request_uri' => $requestUri,
            'expires_in' => (int) ($answer['expires_in'] ?? 0),
            'request_object' => $requestObject,
        ];
    }

    /**
     * RFC 9126 §4: what the browser carries is the client and the request URI, and nothing else.
     */
    public function authorizationUri(string $requestUri): string
    {
        return $this->endpoint($this->metadata(), 'authorization_endpoint') . '?' . http_build_query([
            'client_id' => $this->clientId,
            'request_uri' => $requestUri,
        ], '', '&', \PHP_QUERY_RFC3986);
    }

    /**
     * JARM §4.1: the authorization response is one parameter, a JWT signed by the provider, whose claims
     * are the parameters. Reading them means verifying that signature first, so that what the client
     * acts on is what the provider said and not what the browser carried.
     *
     * @return array<string, mixed>
     */
    public function readAuthorizationResponse(string $response): array
    {
        $claims = $this->verify($response);
        if (($claims['iss'] ?? null) !== $this->issuer()) {
            throw new FapiException('The signed authorization response does not name this provider (JARM section 4.1).');
        }
        if (! $this->audienceMatches($claims['aud'] ?? null)) {
            throw new FapiException('The signed authorization response is not for this client (JARM section 4.1).');
        }
        $expiresAt = $claims['exp'] ?? null;
        if (! is_int($expiresAt) || $expiresAt <= $this->now()) {
            throw new FapiException('The signed authorization response has expired (JARM section 4.1).');
        }

        return $claims;
    }

    /**
     * RFC 9449 §5: the code is exchanged with a proof of possession, and what comes back is bound to the
     * key of that proof, which the provider names in the "cnf" of the access token.
     *
     * @return array<string, mixed> the token response
     */
    public function exchange(string $code, string $codeVerifier, JWK $proofKey): array
    {
        $tokenEndpoint = $this->endpoint($this->metadata(), 'token_endpoint');
        $answer = $this->json('POST', $tokenEndpoint, [
            'headers' => [
                'DPoP' => $this->proof('POST', $tokenEndpoint, $proofKey),
            ],
            'body' => [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->redirectUri,
                'code_verifier' => $codeVerifier,
                'client_id' => $this->clientId,
                ...$this->clientAssertion(),
            ],
        ]);

        if (! is_string($answer['access_token'] ?? null) || ! is_string($answer['id_token'] ?? null)) {
            throw new FapiException(sprintf('The token endpoint answered no token: %s', json_encode($answer)));
        }

        return $answer;
    }

    /**
     * OIDC Core §3.1.3.7: the ID token as the provider issued it for this client, signed and then
     * encrypted to the key the client publishes. It is opened, verified, and what it says of the request
     * it answers is checked: the issuer, the audience, the moment, and the nonce of this very login.
     *
     * @return array{claims: array<string, mixed>, encrypted: bool, algorithm: string, encryption: string|null}
     */
    public function readIdToken(string $idToken, string $nonce): array
    {
        $encryption = null;
        $encrypted = substr_count($idToken, '.') === 4;
        if ($encrypted) {
            [$idToken, $encryption] = $this->decrypt($idToken);
        }
        $claims = $this->verify($idToken);
        if (($claims['iss'] ?? null) !== $this->issuer()) {
            throw new FapiException('The ID token does not name this provider (OIDC Core section 3.1.3.7).');
        }
        if (! $this->audienceMatches($claims['aud'] ?? null)) {
            throw new FapiException('The ID token is not for this client (OIDC Core section 3.1.3.7).');
        }
        if (! hash_equals($nonce, (string) ($claims['nonce'] ?? ''))) {
            throw new FapiException('The ID token does not carry the nonce of this login (OIDC Core section 3.1.3.7).');
        }
        $expiresAt = $claims['exp'] ?? null;
        if (! is_int($expiresAt) || $expiresAt <= $this->now()) {
            throw new FapiException('The ID token has expired (OIDC Core section 3.1.3.7).');
        }

        return [
            'claims' => $claims,
            'encrypted' => $encrypted,
            'algorithm' => (string) ($this->header($idToken)['alg'] ?? '?'),
            'encryption' => $encryption,
        ];
    }

    /**
     * OIDC Core §5.3.2 and RFC 9449 §7.1: the UserInfo answer of a client that registered a signature is
     * a JWT, encrypted to it when it registered that too, and the request that asks for it presents a
     * bound access token with a proof naming it.
     *
     * @return array{claims: array<string, mixed>, content_type: string, encrypted: bool}
     */
    public function userInfo(string $accessToken, JWK $proofKey): array
    {
        $endpoint = $this->endpoint($this->metadata(), 'userinfo_endpoint');
        $response = $this->httpClient->request('GET', $endpoint, [
            'max_redirects' => 0,
            'headers' => [
                'Authorization' => 'DPoP ' . $accessToken,
                'DPoP' => $this->proof('GET', $endpoint, $proofKey, $accessToken),
            ],
        ]);
        if ($response->getStatusCode() !== 200) {
            throw new FapiException(sprintf('UserInfo answered %d: %s', $response->getStatusCode(), $response->getContent(false)));
        }

        $contentType = (string) ($response->getHeaders(false)['content-type'][0] ?? '');
        $body = $response->getContent(false);
        if (! str_contains($contentType, 'jwt')) {
            $claims = json_decode($body, true);

            return [
                'claims' => is_array($claims) ? $claims : [],
                'content_type' => $contentType,
                'encrypted' => false,
            ];
        }

        $encrypted = substr_count($body, '.') === 4;
        if ($encrypted) {
            [$body] = $this->decrypt($body);
        }

        return [
            'claims' => $this->verify($body),
            'content_type' => $contentType,
            'encrypted' => $encrypted,
        ];
    }

    /**
     * RP-Initiated Logout §2: where the browser is sent to end the session at the provider, the ID token
     * of the login naming which session it is.
     */
    public function endSessionUri(string $idToken, string $postLogoutRedirectUri): ?string
    {
        $endpoint = $this->metadata()['end_session_endpoint'] ?? null;
        if (! is_string($endpoint) || $endpoint === '') {
            return null;
        }

        return $endpoint . '?' . http_build_query([
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => $postLogoutRedirectUri,
            'client_id' => $this->clientId,
        ], '', '&', \PHP_QUERY_RFC3986);
    }

    /**
     * A key of this client, held for one login: the pair whose possession every request of that login
     * proves (RFC 9449 §4).
     */
    public static function proofKey(): JWK
    {
        return \Jose\Component\KeyManagement\JWKFactory::createECKey('P-256', [
            'alg' => 'ES256',
            'use' => 'sig',
        ]);
    }

    /**
     * RFC 7638 §3: how a key names itself, which is what a bound token carries in "cnf.jkt".
     */
    public static function thumbprint(JWK $key): string
    {
        return $key->toPublic()->thumbprint('sha256');
    }

    /**
     * RFC 7523 §2.2: this client authenticates by signing an assertion rather than by sending a secret.
     * Its audience is the issuer alone, which is what FAPI 2.0 §5.2.2 asks for.
     *
     * @return array<string, string>
     */
    private function clientAssertion(): array
    {
        return [
            'client_assertion_type' => self::ASSERTION_TYPE,
            'client_assertion' => $this->sign([
                'iss' => $this->clientId,
                'sub' => $this->clientId,
                'aud' => $this->issuer(),
                'jti' => bin2hex(random_bytes(16)),
                'iat' => $this->now(),
                'exp' => $this->now() + self::LIFETIME,
            ]),
        ];
    }

    /**
     * RFC 9449 §4.2: a proof is a JWT carrying the public key it is signed with, naming the request it
     * was made for, and naming the access token when the request presents one (§7.1).
     */
    private function proof(string $method, string $url, JWK $key, ?string $accessToken = null): string
    {
        $claims = [
            'jti' => bin2hex(random_bytes(16)),
            'htm' => $method,
            'htu' => $url,
            'iat' => $this->now(),
        ];
        if ($accessToken !== null) {
            $claims['ath'] = self::base64Url(hash('sha256', $accessToken, true));
        }

        return $this->jws->serialize(
            (new JWSBuilder($this->signatureAlgorithms))
                ->create()
                ->withPayload((string) json_encode($claims, \JSON_THROW_ON_ERROR))
                ->addSignature($key, [
                    'typ' => self::PROOF_TYPE,
                    'alg' => 'ES256',
                    'jwk' => $key->toPublic()->all(),
                ])
                ->build()
        );
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function sign(array $claims, ?string $type = null): string
    {
        $key = $this->key($this->signatureKey);
        $header = [
            'alg' => 'ES256',
            'kid' => $key->has('kid') ? $key->get('kid') : null,
            'typ' => $type,
        ];

        return $this->jws->serialize(
            (new JWSBuilder($this->signatureAlgorithms))
                ->create()
                ->withPayload((string) json_encode($claims, \JSON_THROW_ON_ERROR))
                ->addSignature($key, array_filter($header, static fn ($value) => $value !== null))
                ->build()
        );
    }

    /**
     * The claims of a JWT the provider signed, verified against the keys it publishes and against no
     * other, the algorithm being one of those this client accepts.
     *
     * @return array<string, mixed>
     */
    private function verify(string $token): array
    {
        try {
            $jws = $this->jws->unserialize($token);
        } catch (\Throwable $exception) {
            throw new FapiException('The provider sent something that is not a compact JWS.', previous: $exception);
        }
        $verifier = new JWSVerifier($this->signatureAlgorithms);
        $verified = method_exists($verifier, 'verify')
            ? $verifier->verify($jws, $this->providerKeys(), 0)->isVerified()
            : $verifier->verifyWithKeySet($jws, $this->providerKeys(), 0);
        if (! $verified) {
            throw new FapiException('The signature of the provider does not verify against its JWK Set.');
        }
        $claims = json_decode((string) $jws->getPayload(), true);
        if (! is_array($claims)) {
            throw new FapiException('What the provider signed is not a JSON object.');
        }

        /** @var array<string, mixed> $claims */
        return $claims;
    }

    /**
     * What the provider encrypted to the key this client publishes, opened with its private half.
     *
     * @return array{string, string} the token it held, and how it was encrypted
     */
    private function decrypt(string $token): array
    {
        try {
            $jwe = $this->jwe->unserialize($token);
        } catch (\Throwable $exception) {
            throw new FapiException('The provider sent something that is not a compact JWE.', previous: $exception);
        }
        if (! (new JWEDecrypter($this->encryptionAlgorithms))->decryptUsingKey($jwe, $this->key($this->encryptionKey), 0)) {
            throw new FapiException('What the provider encrypted cannot be opened with the key this client publishes.');
        }
        $header = $jwe->getSharedProtectedHeader();

        return [
            (string) $jwe->getPayload(),
            sprintf('%s / %s', $header['alg'] ?? '?', $header['enc'] ?? '?'),
        ];
    }

    private function providerKeys(): JWKSet
    {
        /** @var array<string, mixed> $keys */
        $keys = $this->cache->get('fapi.jwks.' . hash('xxh128', $this->providerUri), function (ItemInterface $item): array {
            $item->expiresAfter(3600);

            return $this->json('GET', $this->endpoint($this->metadata(), 'jwks_uri'));
        });

        return JWKSet::createFromKeyData($keys);
    }

    /**
     * @return array<string, mixed>
     */
    private function header(string $token): array
    {
        $header = json_decode((string) base64_decode(strtr(explode('.', $token)[0] ?? '', '-_', '+/'), true), true);

        return is_array($header) ? $header : [];
    }

    private function key(string $base64): JWK
    {
        $values = json_decode((string) base64_decode($base64, true), true);
        if (! is_array($values)) {
            throw new FapiException('This rung holds no key: run "castor provision" and then "castor demo".');
        }

        /** @var array<string, mixed> $values */
        return new JWK($values);
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return array<string, mixed>
     */
    private function json(string $method, string $url, array $options = []): array
    {
        $response = $this->httpClient->request($method, $url, [
            'max_redirects' => 0,
            ...$options,
        ]);
        $values = json_decode($response->getContent(false), true);
        if (! is_array($values)) {
            throw new FapiException(sprintf('%s answered %d, which is no JSON object.', $url, $response->getStatusCode()));
        }

        /** @var array<string, mixed> $values */
        return $values;
    }

    /**
     * @param array<string, mixed> $metadata
     */
    private function endpoint(array $metadata, string $name): string
    {
        $endpoint = $metadata[$name] ?? null;
        if (! is_string($endpoint) || $endpoint === '') {
            throw new FapiException(sprintf('The provider announces no "%s".', $name));
        }

        return $endpoint;
    }

    private function issuer(): string
    {
        return (string) ($this->metadata()['issuer'] ?? $this->providerUri);
    }

    private function audienceMatches(mixed $audience): bool
    {
        $audiences = array_filter(is_array($audience) ? $audience : [$audience], is_string(...));

        return in_array($this->clientId, $audiences, true);
    }

    private function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }

    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
