<?php

declare(strict_types=1);

namespace App\Forge\Composed;

use App\Forge\Chosen;
use App\Forge\Offer;

/**
 * How the authorization request travels and how the answer to it comes back: the response mode (OAuth 2.0
 * Multiple Response Type Encoding Practices §2.1, Form Post Response Mode, JARM §4), whether the request
 * is pushed to the provider instead of being put in the URL of a browser (RFC 9126 §2), and whether it is
 * signed as a request object (RFC 9101 §4).
 *
 * The three are composed apart because they are apart on the wire: a request can be pushed in clear, put
 * in the URL signed, or pushed and signed, which is what the last rung of the ladder did.
 */
final readonly class TheRequest
{
    /**
     * OIDC Core §3.1.2.1: what a client may ask of the provider about the interaction. "none" is not
     * offered: a first login answers it with "login_required", which is a refusal and not a flow.
     */
    public const array PROMPTS = ['login', 'consent', 'select_account'];

    public function __construct(
        public string $responseMode,
        public bool $pushed,
        public bool $requiresPushed,
        public ?string $requestObjectSigningAlgorithm,
        public bool $requiresASignedRequestObject,
        public ?string $acrValues,
        public ?string $prompt,
    ) {
    }

    /**
     * @param array<string, mixed> $input
     *
     * @throws \App\Forge\ForgeException when the provider offers none of what was composed
     */
    public static function read(array $input, Offer $offer): self
    {
        $signing = array_values(array_filter(
            $offer->names('request_object_signing_alg_values_supported'),
            static fn (string $algorithm): bool => $algorithm !== 'none',
        ));

        return new self(
            Chosen::one($input['response_mode'] ?? null, $offer->names('response_modes_supported'), 'response_mode'),
            Chosen::asked($input['pushed'] ?? null),
            Chosen::asked($input['require_pushed_authorization_requests'] ?? null),
            Chosen::orNone($input['request_object_signing_alg'] ?? null, $signing, 'request_object_signing_alg'),
            Chosen::asked($input['require_signed_request_object'] ?? null),
            Chosen::orNone($input['acr_values'] ?? null, $offer->names('acr_values_supported'), 'acr_values'),
            Chosen::orNone($input['prompt'] ?? null, self::PROMPTS, 'prompt'),
        );
    }

    /**
     * JARM §4.3: the modes whose response is one signed parameter, which the provider resolves from the
     * alias "jwt" to the mode of the response type.
     */
    public function isSigned(): bool
    {
        return str_ends_with($this->responseMode, 'jwt');
    }

    /**
     * Form Post Response Mode: the mode whose response comes back as a self-submitting page rather than
     * in the URL, whether it is signed or not.
     */
    public function isPosted(): bool
    {
        return str_starts_with($this->responseMode, 'form_post');
    }

    public function isSignedAsARequestObject(): bool
    {
        return $this->requestObjectSigningAlgorithm !== null;
    }

    /**
     * @return array<string, mixed>
     */
    public function registration(): array
    {
        return array_filter([
            'require_pushed_authorization_requests' => $this->requiresPushed,
            'require_signed_request_object' => $this->requiresASignedRequestObject,
            'request_object_signing_alg' => $this->requestObjectSigningAlgorithm,
        ], static fn (mixed $value): bool => $value !== null && $value !== false);
    }

    /**
     * What this family adds to the authorization request itself, beside the response mode the flow writes.
     *
     * @return array<string, string>
     */
    public function parameters(): array
    {
        return array_filter([
            'acr_values' => $this->acrValues,
            'prompt' => $this->prompt,
        ], static fn (?string $value): bool => $value !== null);
    }
}
