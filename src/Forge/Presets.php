<?php

declare(strict_types=1);

namespace App\Forge;

/**
 * The presets of the forge: five of the six clients the ladder of rungs registered by hand (beffroi#201),
 * plus the three the ladder had no rung for, written as compositions of the form.
 *
 * The rung that is not here is the opaque one: the shape of the access token is one of the members this
 * provider writes itself and a client never registers (decision 0009), so a client of the forge cannot
 * ask for it. The two shapes are seen on the declared clients of the configuration, which
 * `castor demo --resource-server` signs in as.
 *
 * They are here for what a preset is good for and for nothing else: a visitor who wants to see FAPI 2.0
 * rather than compose it, and a walk that needs the same client twice to assert the same thing twice
 * (`castor demo --ladder`). Everything they hold is a value the provider announces, so a preset that names
 * something it stopped offering is refused on the page like any other composition, which is what tells us.
 */
final readonly class Presets
{
    public function __construct(
        private string $resource,
    ) {
    }

    /**
     * @return array<string, Preset>
     */
    public function all(): array
    {
        $presets = [
            new Preset('basic', 'Everything in the open', 'The starting point: the request in the query, a secret in a header, a token anybody can read.', [
                'client_name' => 'Forged: everything in the open',
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => ['profile', 'email'],
                'response_mode' => 'query',
            ]),
            new Preset('form-post', 'A posted response', 'The response stops travelling in the URL: the provider answers with a page that posts it back.', [
                'client_name' => 'Forged: a posted response',
                'token_endpoint_auth_method' => 'client_secret_post',
                'scope' => ['profile', 'email'],
                'response_mode' => 'form_post',
            ]),
            new Preset('key', 'A key instead of a secret', 'The client shares no secret any more: it signs an assertion, and it is told of a logout both ways.', [
                'client_name' => 'Forged: a key instead of a secret',
                'token_endpoint_auth_method' => 'private_key_jwt',
                'scope' => ['profile', 'email'],
                'response_mode' => 'query',
                'frontchannel_logout' => true,
                'backchannel_logout' => true,
                'logout_session_required' => true,
            ]),
            new Preset('rar', 'What it may do, not what kind', 'The client asks what it may do, to what, and up to how much, instead of asking for a kind of thing.', [
                'client_name' => 'Forged: what it may do',
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => ['profile', 'invoices.read'],
                'response_mode' => 'query',
                'authorization_details_type' => 'invoice_payment',
                'authorization_details' => $this->invoicePayment(),
            ]),
            new Preset('fapi', 'FAPI 2.0, bound to a key', 'Nothing travels through the browser in clear: the request is pushed and signed, the response signed, the token bound to a key, the documents encrypted.', [
                'client_name' => 'Forged: FAPI 2.0 with DPoP',
                'token_endpoint_auth_method' => 'private_key_jwt',
                'scope' => ['profile', 'email'],
                'response_mode' => 'jwt',
                'authorization_signed_response_alg' => 'ES256',
                'pushed' => true,
                'require_pushed_authorization_requests' => true,
                'request_object_signing_alg' => 'ES256',
                'require_signed_request_object' => true,
                'token_binding' => 'dpop',
                'dpop_signing_alg' => 'ES256',
                'id_token_signed_response_alg' => 'ES256',
                'id_token_encrypted_response_alg' => 'RSA-OAEP-256',
                'userinfo_signed_response_alg' => 'ES256',
                'userinfo_encrypted_response_alg' => 'RSA-OAEP-256',
                'frontchannel_logout' => true,
                'backchannel_logout' => true,
            ]),
            new Preset('fapi-mtls', 'FAPI 2.0, bound to a certificate', 'The same profile, the other way of proving who asks: the certificate of the connection authenticates the client and the token is bound to it.', [
                'client_name' => 'Forged: FAPI 2.0 with mTLS',
                'token_endpoint_auth_method' => 'self_signed_tls_client_auth',
                'scope' => ['profile', 'email'],
                'response_mode' => 'jwt',
                'authorization_signed_response_alg' => 'ES256',
                'pushed' => true,
                'require_pushed_authorization_requests' => true,
                'request_object_signing_alg' => 'ES256',
                'token_binding' => 'mtls',
                'tls_client_certificate_bound_access_tokens' => true,
                'id_token_signed_response_alg' => 'ES256',
                'frontchannel_logout' => true,
            ]),
            new Preset('pairwise', 'A "sub" of its own', 'The same user, an identifier this client alone sees (OIDC Core §8), and an ID token encrypted to it.', [
                'client_name' => 'Forged: a sub of its own',
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => ['profile', 'email'],
                'response_mode' => 'query',
                'subject_type' => 'pairwise',
                'id_token_encrypted_response_alg' => 'RSA-OAEP-256',
            ]),
            new Preset('public', 'A client with no credential', 'A public client: it holds no secret and no key, and PKCE is what ties the code to whoever asked for it.', [
                'client_name' => 'Forged: no credential at all',
                'token_endpoint_auth_method' => 'none',
                'scope' => ['profile'],
                'response_mode' => 'query',
            ]),
        ];

        $all = [];
        foreach ($presets as $preset) {
            $all[$preset->slug] = $preset;
        }

        return $all;
    }

    /**
     * @throws ForgeException when nothing of that name is written down
     */
    public function of(string $slug): Preset
    {
        return $this->all()[$slug] ?? throw new ForgeException(sprintf('The forge holds no preset called "%s".', $slug));
    }

    /**
     * RFC 9396 §2: the detail the "invoice_payment" type of the provider reads, on the invoice
     * `castor demo --rar` pays and for the resource of this demonstration.
     */
    private function invoicePayment(): string
    {
        return (string) json_encode([[
            'type' => 'invoice_payment',
            'locations' => [$this->resource],
            'actions' => ['pay', 'read'],
            'identifier' => 'INV-4711',
            'maximumAmount' => [
                'currency' => 'EUR',
                'amount' => '45.00',
            ],
        ]], \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES);
    }
}
