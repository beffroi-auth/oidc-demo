<?php

declare(strict_types=1);

namespace App\Forge;

use App\Forge\Composed\Credentials;
use App\Forge\Composed\TheDocuments;
use App\Forge\Composed\TheLogout;
use App\Forge\Composed\TheRequest;
use App\Forge\Composed\TheTokens;
use App\Forge\Composed\WhatItAsksFor;

/**
 * A client as it was composed on the page of the forge, before it exists at the provider: six families of
 * choices, each one read from what the provider announces, and the two members that belong to none of
 * them, the name the consent page shows and the kind of "sub" this client sees (OIDC Core §8).
 *
 * It is what a preset is, what the form submits and what the registration of the client is written from,
 * so the three cannot disagree: a preset is a composition and not a client of its own, and the form is
 * submitted whether it was filled by hand or by a preset.
 */
final readonly class Composition
{
    public function __construct(
        public string $name,
        public Credentials $credentials,
        public TheRequest $request,
        public TheDocuments $documents,
        public TheTokens $tokens,
        public WhatItAsksFor $asksFor,
        public TheLogout $logout,
        public string $subjectType,
    ) {
    }

    /**
     * @param array<string, mixed> $input what the form submitted, or what a preset holds
     *
     * @throws ForgeException when the provider offers none of what was composed
     */
    public static function read(array $input, Offer $offer): self
    {
        $name = is_string($input['client_name'] ?? null) ? trim($input['client_name']) : '';

        return new self(
            $name === '' ? 'A client of the forge' : $name,
            Credentials::read($input, $offer),
            TheRequest::read($input, $offer),
            TheDocuments::read($input, $offer),
            TheTokens::read($input, $offer),
            WhatItAsksFor::read($input, $offer),
            TheLogout::read($input, $offer),
            Chosen::one($input['subject_type'] ?? 'public', $offer->names('subject_types_supported'), 'subject_type'),
        );
    }

    /**
     * The registration of this client (RFC 7591 §2, OIDC Registration §2), every member coming from the
     * family it belongs to. What the forge adds to it is what it draws for this client and nothing else:
     * the keys it publishes, the certificate it presents, and the URIs of its own routes.
     *
     * @param list<string> $redirectUris
     *
     * @return array<string, mixed>
     */
    public function registration(array $redirectUris, string $postLogoutRedirectUri, string $frontChannelLogoutUri, string $backChannelLogoutUri): array
    {
        return [
            'client_name' => $this->name,
            'redirect_uris' => $redirectUris,
            'post_logout_redirect_uris' => [$postLogoutRedirectUri],
            'response_types' => ['code'],
            'grant_types' => $this->asksFor->asksForARefreshToken()
                ? ['authorization_code', 'refresh_token']
                : ['authorization_code'],
            'subject_type' => $this->subjectType,
            ...$this->credentials->registration(),
            ...$this->request->registration(),
            ...$this->documents->registration(),
            ...$this->tokens->registration(),
            ...$this->asksFor->registration(),
            ...$this->logout->registration($frontChannelLogoutUri, $backChannelLogoutUri),
        ];
    }

    /**
     * What this client sends at the authorization endpoint beside what the flow writes for it: the
     * parameters of the two families that have any, in one place so that a flow never reads a family.
     *
     * @return array<string, string>
     */
    public function parameters(): array
    {
        return [
            ...$this->asksFor->parameters(),
            ...$this->request->parameters(),
        ];
    }

    /**
     * Whether this client has to publish a key set: the ones it receives an encrypted document with, and
     * the one it signs with when it proves a key or signs its requests (RFC 7591 §2 "jwks").
     */
    public function needsASigningKey(): bool
    {
        return $this->request->isSignedAsARequestObject();
    }
}
