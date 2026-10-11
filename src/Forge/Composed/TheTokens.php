<?php

declare(strict_types=1);

namespace App\Forge\Composed;

use App\Forge\Chosen;
use App\Forge\Offer;

/**
 * How the client holds what the token endpoint issues it: as a bearer token anybody holding it can spend
 * (RFC 6750 §1.2), bound to a key it proves at every request (RFC 9449), or bound to the certificate it
 * presents (RFC 8705 §3).
 *
 * The binding is a thing the client does and not a thing it registers: a client that sends a proof gets a
 * token bound to its key, and one that presents a certificate can register that its tokens are bound to
 * it whichever way it authenticated (RFC 8705 §3.4).
 *
 * What shape the access token takes, a self-contained "at+jwt" or an opaque one, is not here and cannot
 * be: it is one of the seven members this provider writes itself, by a declaration or by the registration
 * policy of the tenant, and a client that asks for one is refused (decision 0009). The page of a built
 * client therefore reads the shape off the token it was issued, rather than saying what it asked for.
 */
final readonly class TheTokens
{
    public function __construct(
        public string $binding,
        public ?string $dpopSigningAlgorithm,
        public bool $requiresCertificateBound,
    ) {
    }

    /**
     * @param array<string, mixed> $input
     *
     * @throws \App\Forge\ForgeException when the provider offers none of what was composed
     */
    public static function read(array $input, Offer $offer): self
    {
        $binding = Chosen::one($input['token_binding'] ?? 'none', Offer::TOKEN_BINDINGS, 'token_binding');
        $algorithms = $offer->names('dpop_signing_alg_values_supported');

        return new self(
            $binding,
            $binding === 'dpop' ? Chosen::one($input['dpop_signing_alg'] ?? ($algorithms[0] ?? null), $algorithms, 'dpop_signing_alg') : null,
            Chosen::asked($input['tls_client_certificate_bound_access_tokens'] ?? null),
        );
    }

    public function areBoundToAKey(): bool
    {
        return $this->binding === 'dpop';
    }

    public function areBoundToACertificate(): bool
    {
        return $this->binding === 'mtls';
    }

    /**
     * @return array<string, mixed>
     */
    public function registration(): array
    {
        return array_filter([
            'tls_client_certificate_bound_access_tokens' => $this->requiresCertificateBound,
        ], static fn (mixed $value): bool => $value !== false);
    }
}
