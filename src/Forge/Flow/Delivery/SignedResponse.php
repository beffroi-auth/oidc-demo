<?php

declare(strict_types=1);

namespace App\Forge\Flow\Delivery;

use App\Forge\BuiltClient;
use App\Forge\Flow\Jwt;
use App\Forge\ForgeException;
use App\Forge\Offer;

/**
 * JARM §4.1: the one signed parameter an authorization response can be, read once for the two modes that
 * carry it. It is opened when the client registered an encryption for it (JARM §4.2), verified against
 * the keys of the provider, and what it says of itself is checked before any parameter of it is read: the
 * issuer that signed it, the client it was signed for, and the moment it stops being good for.
 */
final readonly class SignedResponse
{
    public function __construct(
        private Jwt $jwt,
        private Offer $offer,
    ) {
    }

    /**
     * @return array{parameters: array<string, mixed>, carried: string, payload: string|null}
     *
     * @throws ForgeException when there is no such parameter, or what it holds does not hold together
     */
    public function read(?string $response, BuiltClient $client): array
    {
        if (! is_string($response) || $response === '') {
            throw new ForgeException('The provider answered without the signed response JARM §4.1 defines.');
        }

        $encryption = null;
        $signed = $response;
        if ($this->jwt->isEncrypted($response)) {
            $algorithm = is_string($client->registration['authorization_encrypted_response_alg'] ?? null)
                ? $client->registration['authorization_encrypted_response_alg']
                : throw new ForgeException('The provider encrypted the authorization response to a client that registered no encryption for it.');
            [$signed, $encryption] = $this->jwt->decrypt($response, $client->material->encryptionJwk($algorithm));
        }

        $claims = $this->jwt->verify($signed);
        if (($claims['iss'] ?? null) !== $this->offer->issuer()) {
            throw new ForgeException('The signed authorization response does not name this provider (JARM §4.1).');
        }
        $audiences = array_filter(is_array($claims['aud'] ?? null) ? $claims['aud'] : [$claims['aud'] ?? null], is_string(...));
        if (! in_array($client->clientId, $audiences, true)) {
            throw new ForgeException('The signed authorization response is not for this client (JARM §4.1).');
        }
        $expiresAt = $claims['exp'] ?? null;
        if (! is_int($expiresAt) || $expiresAt <= $this->jwt->now()) {
            throw new ForgeException('The signed authorization response has expired (JARM §4.1).');
        }

        return [
            'parameters' => $claims,
            'carried' => sprintf(
                'one "response" of %d characters, %s, holding %s',
                strlen($response),
                $encryption === null
                    ? sprintf('a JWS signed %s', $this->jwt->header($signed)['alg'] ?? '?')
                    : sprintf('a JWE %s then a JWS signed %s', $encryption, $this->jwt->header($signed)['alg'] ?? '?'),
                implode(', ', array_keys($claims)),
            ),
            'payload' => $response,
        ];
    }
}
