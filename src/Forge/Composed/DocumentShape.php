<?php

declare(strict_types=1);

namespace App\Forge\Composed;

use App\Forge\Chosen;
use App\Forge\Offer;

/**
 * The shape one document of the provider takes for this client: signed with an algorithm it registered,
 * and encrypted to a key it publishes when it registered that too (OIDC Core §3.1.3.7 for the ID token,
 * §5.3.2 for the UserInfo answer, JARM §3 for the authorization response).
 *
 * The three documents register the same three members under their own prefix, and the provider announces
 * what it offers for each under that same prefix, so this is written once and read three times.
 */
final readonly class DocumentShape
{
    public function __construct(
        public ?string $signing,
        public ?string $keyEncryption,
        public ?string $contentEncryption,
    ) {
    }

    /**
     * @param array<string, mixed> $input
     *
     * @throws \App\Forge\ForgeException when the provider offers none of what was composed
     */
    public static function read(array $input, Offer $offer, string $prefix): self
    {
        $signing = Chosen::orNone(
            $input[$prefix . '_signed_response_alg'] ?? null,
            $offer->names($prefix . '_signing_alg_values_supported'),
            $prefix . '_signed_response_alg',
        );
        $keyEncryption = Chosen::orNone(
            $input[$prefix . '_encrypted_response_alg'] ?? null,
            $offer->keyEncryptionAlgorithms($prefix),
            $prefix . '_encrypted_response_alg',
        );
        $contentEncryption = $keyEncryption === null ? null : Chosen::one(
            $input[$prefix . '_encrypted_response_enc'] ?? ($offer->contentEncryptionAlgorithms($prefix)[0] ?? null),
            $offer->contentEncryptionAlgorithms($prefix),
            $prefix . '_encrypted_response_enc',
        );

        return new self($signing, $keyEncryption, $contentEncryption);
    }

    public function isEncrypted(): bool
    {
        return $this->keyEncryption !== null;
    }

    /**
     * @return array<string, string>
     */
    public function registration(string $prefix): array
    {
        return array_filter([
            $prefix . '_signed_response_alg' => $this->signing,
            $prefix . '_encrypted_response_alg' => $this->keyEncryption,
            $prefix . '_encrypted_response_enc' => $this->contentEncryption,
        ], static fn (?string $value): bool => $value !== null);
    }

    public function describe(string $plain): string
    {
        return match (true) {
            $this->isEncrypted() => sprintf('signed %s, then encrypted %s / %s to the key this client publishes', $this->signing ?? 'by default', $this->keyEncryption, $this->contentEncryption),
            $this->signing !== null => sprintf('signed %s', $this->signing),
            default => $plain,
        };
    }
}
