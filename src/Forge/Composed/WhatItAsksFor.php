<?php

declare(strict_types=1);

namespace App\Forge\Composed;

use App\Forge\Chosen;
use App\Forge\ForgeException;
use App\Forge\Offer;

/**
 * What the client asks the user for: the scopes (RFC 6749 §3.3), and the detail of what it may do, to what
 * and up to how much (RFC 9396 §2).
 *
 * "openid" is in every composition, this being a client that signs a user in, and "offline_access" brings
 * the grant that spends what it obtains: a scope that asks for a refresh token and a client not registered
 * for "refresh_token" would be refused at the token endpoint rather than at the authorization one.
 *
 * The resource a token is addressed to (RFC 8707 §2) is not here: the list of resources a client may ask a
 * token for is one of the seven members this provider writes itself and a client never registers, and a
 * resource outside the registered list is "invalid_target" (decision 0009). A client of the forge asks for
 * none, and its tokens are addressed to itself.
 */
final readonly class WhatItAsksFor
{
    /**
     * @param list<string> $scopes
     */
    public function __construct(
        public array $scopes,
        public ?string $authorizationDetailsType,
        public ?string $authorizationDetails,
    ) {
    }

    /**
     * @param array<string, mixed> $input
     *
     * @throws ForgeException when the provider offers none of what was composed, or the detail is no JSON array
     */
    public static function read(array $input, Offer $offer): self
    {
        $type = Chosen::orNone(
            $input['authorization_details_type'] ?? null,
            $offer->names('authorization_details_types_supported'),
            'authorization_details_type',
        );
        $details = is_string($input['authorization_details'] ?? null) ? trim($input['authorization_details']) : '';
        if ($type !== null && $details !== '') {
            $read = json_decode($details, true);
            if (! is_array($read) || $read === []) {
                throw new ForgeException('What this client asks for in "authorization_details" is no JSON array of details (RFC 9396 §2).');
            }
        }

        return new self(
            ['openid', ...Chosen::several($input['scope'] ?? [], $offer->scopes(), 'scope')],
            $type,
            $type !== null && $details !== '' ? $details : null,
        );
    }

    /**
     * RFC 6749 §6: the grant that spends a refresh token, for a client that asked for one and for no other.
     */
    public function asksForARefreshToken(): bool
    {
        return in_array('offline_access', $this->scopes, true);
    }

    /**
     * @return array<string, mixed>
     */
    public function registration(): array
    {
        return array_filter([
            'scope' => implode(' ', $this->scopes),
            'authorization_details_types' => $this->authorizationDetailsType === null ? null : [$this->authorizationDetailsType],
        ], static fn (mixed $value): bool => $value !== null);
    }

    /**
     * @return array<string, string>
     */
    public function parameters(): array
    {
        return array_filter([
            'scope' => implode(' ', $this->scopes),
            'authorization_details' => $this->authorizationDetails,
        ], static fn (?string $value): bool => $value !== null);
    }
}
