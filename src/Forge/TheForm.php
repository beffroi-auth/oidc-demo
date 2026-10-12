<?php

declare(strict_types=1);

namespace App\Forge;

use App\Forge\Composed\TheRequest;
use App\Forge\Flow\Authentication\ClientAuthentications;
use App\Forge\Flow\Binding\Bindings;
use App\Forge\Flow\Delivery\Deliveries;

/**
 * What the page of the forge offers to compose with: every choice is what the provider announces and what
 * the demonstration can play, which is the two lists crossed and nothing written by hand.
 *
 * So a provider that stops announcing a response mode stops offering it here, and a method the provider
 * serves that the demonstration cannot play is not offered either: it is a gap, and a gap belongs in an
 * issue and not in a form that would fail at the callback.
 */
final readonly class TheForm
{
    /**
     * The members this provider writes itself, by a declaration or by the registration policy of a tenant,
     * and that a client which registers itself is refused rather than obeyed (decision 0009, the list of
     * `RegisteredMembers` in the provider). The form offers none of them, and the page says which they are
     * and why, because "a client cannot ask for this" is a thing worth seeing.
     *
     * @var array<string, string>
     */
    public const array WRITTEN_BY_THE_DEPLOYMENT = [
        'access_token_format' => 'the shape of the access token, self-contained or opaque',
        'resources' => 'the resources it may ask a token for (RFC 8707 §2); a client that registers none asks for none',
        'require_sender_constrained_tokens' => 'that its tokens are never bearer tokens (FAPI 2.0 §5.3.1)',
        'requires_consent' => 'that the consent page may be skipped for it',
        'requires_pkce' => 'that PKCE may be dispensed with (decision 0017)',
        'token_exchange' => 'what it may exchange a token for (RFC 8693 §2.1)',
        'may_act' => 'who may act for the subject of its tokens (RFC 8693 §4.4)',
    ];

    public function __construct(
        private Offer $offer,
        private ClientAuthentications $authentications,
        private Deliveries $deliveries,
        private Bindings $bindings,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function choices(): array
    {
        return [
            'issuer' => $this->offer->issuer(),
            'reachable' => $this->offer->isReachable(),
            'registers' => is_string($this->offer->document()['registration_endpoint'] ?? null),
            'requires_pushed' => $this->offer->says('require_pushed_authorization_requests'),
            'authentication' => $this->authenticationMethods(),
            'response_modes' => $this->responseModes(),
            'bindings' => $this->tokenBindings(),
            'scopes' => $this->offer->scopes(),
            'dpop_algorithms' => $this->offer->names('dpop_signing_alg_values_supported'),
            'request_object_algorithms' => array_values(array_filter(
                $this->offer->names('request_object_signing_alg_values_supported'),
                static fn (string $algorithm): bool => $algorithm !== 'none',
            )),
            'documents' => [
                'authorization' => $this->document('authorization'),
                'id_token' => $this->document('id_token'),
                'userinfo' => $this->document('userinfo'),
            ],
            'subject_types' => $this->offer->names('subject_types_supported'),
            'authorization_details_types' => $this->offer->names('authorization_details_types_supported'),
            'acr_values' => $this->offer->names('acr_values_supported'),
            'prompts' => TheRequest::PROMPTS,
            'logout' => [
                'frontchannel' => $this->offer->says('frontchannel_logout_supported'),
                'backchannel' => $this->offer->says('backchannel_logout_supported'),
            ],
            'mutual_tls' => $this->offer->mutualTlsEndpoints() !== [],
            // decision 0009: what the provider writes itself, which the page says rather than offering
            'written_by_the_deployment' => self::WRITTEN_BY_THE_DEPLOYMENT,
        ];
    }

    /**
     * @return list<array{name: string, describe: string}>
     */
    private function authenticationMethods(): array
    {
        $offered = [];
        foreach ($this->offer->names('token_endpoint_auth_methods_supported') as $name) {
            if (in_array($name, $this->authentications->names(), true)) {
                $offered[] = [
                    'name' => $name,
                    'describe' => $this->authentications->named($name)->describe(),
                ];
            }
        }

        return $offered;
    }

    /**
     * @return list<array{name: string, describe: string}>
     */
    private function responseModes(): array
    {
        $offered = [];
        foreach ($this->offer->names('response_modes_supported') as $name) {
            if (in_array($name, $this->deliveries->names(), true)) {
                $offered[] = [
                    'name' => $name,
                    'describe' => $this->deliveries->forMode($name)->describe(),
                ];
            }
        }

        return $offered;
    }

    /**
     * @return list<array{name: string, describe: string}>
     */
    private function tokenBindings(): array
    {
        $offered = [];
        foreach (Offer::TOKEN_BINDINGS as $name) {
            if (! in_array($name, $this->bindings->names(), true)) {
                continue;
            }
            // RFC 8705 §5: a binding to a certificate is only offered by a provider that serves the
            // endpoints which ask for one
            if ($name === 'mtls' && $this->offer->mutualTlsEndpoints() === []) {
                continue;
            }
            $offered[] = [
                'name' => $name,
                'describe' => $this->bindings->named($name)->describe(),
            ];
        }

        return $offered;
    }

    /**
     * @return array{signing: list<string>, encryption: list<string>, content: list<string>}
     */
    private function document(string $prefix): array
    {
        return [
            'signing' => $this->offer->names($prefix . '_signing_alg_values_supported'),
            'encryption' => $this->offer->keyEncryptionAlgorithms($prefix),
            'content' => $this->offer->contentEncryptionAlgorithms($prefix),
        ];
    }
}
