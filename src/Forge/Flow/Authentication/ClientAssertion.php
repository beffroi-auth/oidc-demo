<?php

declare(strict_types=1);

namespace App\Forge\Flow\Authentication;

use App\Forge\BuiltClient;
use App\Forge\Flow\Jwt;
use App\Forge\Offer;
use Jose\Component\Core\JWK;

/**
 * RFC 7523 §2.2: the assertion a client signs in place of sending a secret, written once for the two
 * methods that send one, the key being a pair the client published or the secret it shares.
 *
 * Its audience is the issuer alone, which is what FAPI 2.0 Security Profile §5.2.2 asks for and what
 * every provider accepts, and its "jti" is drawn for each one so that a replayed assertion is one the
 * provider has already seen.
 */
final readonly class ClientAssertion
{
    public const string TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    public function __construct(
        private Jwt $jwt,
        private Offer $offer,
    ) {
    }

    /**
     * @return array<string, string> the two parameters such a request carries
     */
    public function parameters(BuiltClient $client, JWK $key, string $algorithm): array
    {
        return [
            'client_assertion_type' => self::TYPE,
            'client_assertion' => $this->jwt->sign([
                'iss' => $client->clientId,
                'sub' => $client->clientId,
                'aud' => $this->offer->issuer(),
                'jti' => bin2hex(random_bytes(16)),
                'iat' => $this->jwt->now(),
                'exp' => $this->jwt->now() + Jwt::LIFETIME,
            ], $key, $algorithm),
        ];
    }
}
