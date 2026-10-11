<?php

declare(strict_types=1);

namespace App\Forge\Composed;

use App\Forge\Offer;

/**
 * The three documents the provider sends this client, each in the shape the client registered for it: the
 * ID token (OIDC Core §3.1.3.7), the UserInfo answer (§5.3.2) and the authorization response (JARM §3).
 *
 * Which keys the forge has to draw is read here and in one place: a client that registered an encryption
 * algorithm for any of the three publishes a key of that kind, and a client that registered none for any
 * of them publishes a key only if the way it authenticates asks for one.
 */
final readonly class TheDocuments
{
    public function __construct(
        public DocumentShape $idToken,
        public DocumentShape $userInfo,
        public DocumentShape $authorizationResponse,
    ) {
    }

    /**
     * @param array<string, mixed> $input
     *
     * @throws \App\Forge\ForgeException when the provider offers none of what was composed
     */
    public static function read(array $input, Offer $offer): self
    {
        return new self(
            DocumentShape::read($input, $offer, 'id_token'),
            DocumentShape::read($input, $offer, 'userinfo'),
            DocumentShape::read($input, $offer, 'authorization'),
        );
    }

    /**
     * The key encryption algorithms this client has to publish a key for, each once (RFC 7517 §4.2: the
     * "use" of a key says which half of the set it belongs to, and "alg" which algorithm it is for).
     *
     * @return list<string>
     */
    public function keyEncryptionAlgorithms(): array
    {
        $algorithms = array_filter([
            $this->idToken->keyEncryption,
            $this->userInfo->keyEncryption,
            $this->authorizationResponse->keyEncryption,
        ], static fn (?string $algorithm): bool => $algorithm !== null);

        return array_values(array_unique($algorithms));
    }

    public function areEncrypted(): bool
    {
        return $this->keyEncryptionAlgorithms() !== [];
    }

    /**
     * @return array<string, mixed>
     */
    public function registration(): array
    {
        return [
            ...$this->idToken->registration('id_token'),
            ...$this->userInfo->registration('userinfo'),
            ...$this->authorizationResponse->registration('authorization'),
        ];
    }
}
