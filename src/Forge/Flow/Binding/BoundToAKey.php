<?php

declare(strict_types=1);

namespace App\Forge\Flow\Binding;

use App\Forge\BuiltClient;
use App\Forge\Flow\Jwt;
use App\Forge\ForgeException;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;

/**
 * RFC 9449: the client draws a key for the login, proves it on every request it makes, and the provider
 * binds what it issues to that key, naming it in "cnf.jkt". Holding the token is then not enough: a
 * request that cannot sign a proof with the key is refused whatever token it carries.
 */
final readonly class BoundToAKey implements TokenBindingInterface
{
    private const string PROOF_TYPE = 'dpop+jwt';

    public function __construct(
        private Jwt $jwt,
    ) {
    }

    public function name(): string
    {
        return 'dpop';
    }

    public function describe(): string
    {
        return 'dpop: a key drawn for this login, proved on every request, which the provider names in "cnf.jkt" (RFC 9449)';
    }

    public function remember(?string $algorithm): array
    {
        $algorithm ??= 'ES256';

        return [
            'proof_key' => self::key($algorithm)->all(),
            'proof_algorithm' => $algorithm,
        ];
    }

    public function needsTheCertificateEndpoints(): bool
    {
        return false;
    }

    public function scheme(): string
    {
        return 'DPoP';
    }

    public function apply(string $method, string $url, array $options, array $remembered, BuiltClient $client, ?string $accessToken = null): array
    {
        $key = self::proofKey($remembered);
        $algorithm = is_string($remembered['proof_algorithm'] ?? null) ? $remembered['proof_algorithm'] : 'ES256';
        $claims = [
            'jti' => bin2hex(random_bytes(16)),
            'htm' => $method,
            'htu' => $url,
            'iat' => $this->jwt->now(),
        ];
        if ($accessToken !== null) {
            // RFC 9449 §4.2: a proof made for a request that presents a token names that token, so a
            // proof cannot be taken from one request and used on another
            $claims['ath'] = rtrim(strtr(base64_encode(hash('sha256', $accessToken, true)), '+/', '-_'), '=');
        }

        /** @var array<string, mixed> $headers */
        $headers = is_array($options['headers'] ?? null) ? $options['headers'] : [];
        $options['headers'] = [
            ...$headers,
            'DPoP' => $this->jwt->sign($claims, $key, $algorithm, [
                'typ' => self::PROOF_TYPE,
                'jwk' => $key->toPublic()->all(),
                'kid' => null,
            ]),
        ];

        return $options;
    }

    public function confirmation(array $remembered, BuiltClient $client): ?string
    {
        return self::proofKey($remembered)->toPublic()->thumbprint('sha256');
    }

    /**
     * @param array<string, mixed> $remembered
     *
     * @throws ForgeException when this login remembered no key
     */
    private static function proofKey(array $remembered): JWK
    {
        $values = $remembered['proof_key'] ?? null;
        if (! is_array($values)) {
            throw new ForgeException('This login drew no key to bind its tokens to.');
        }

        /** @var array<string, mixed> $values */
        return new JWK($values);
    }

    /**
     * @throws ForgeException when no key of that algorithm is drawn here
     */
    private static function key(string $algorithm): JWK
    {
        $parameters = [
            'alg' => $algorithm,
            'use' => 'sig',
        ];

        return match ($algorithm) {
            'ES256' => JWKFactory::createECKey('P-256', $parameters),
            'ES384' => JWKFactory::createECKey('P-384', $parameters),
            'ES512' => JWKFactory::createECKey('P-521', $parameters),
            'EdDSA' => JWKFactory::createOKPKey('Ed25519', $parameters),
            'RS256', 'PS256' => JWKFactory::createRSAKey(2048, $parameters),
            default => throw new ForgeException(sprintf('The forge draws no proof key for "%s".', $algorithm)),
        };
    }
}
