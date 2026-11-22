<?php

declare(strict_types=1);

namespace App\Forge;

/**
 * The presets of the forge, written as compositions of the form: one client per feature of the provider,
 * each one adding to the first what makes that feature and nothing else, so that what differs from the
 * first is what the feature is.
 *
 * None asks for an opaque access token: the shape of the access token is one of the members this provider
 * writes itself and a client never registers (decision 0009), so a client of the forge cannot ask for it.
 * The two shapes are seen on the declared clients of the configuration, which
 * `castor demo --resource-server` signs in as.
 *
 * `castor demo --forge` builds the eight first ones and asserts what each one holds, so their slugs and
 * their forms are what that walk reads. Everything they hold is a value the provider announces, so a preset
 * that names something it stopped offering is refused on the page like any other composition, which is
 * what tells us.
 */
final readonly class Presets
{
    public const string BASELINE = 'basic';

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
            new Preset('basic', 'Code + PKCE', 'Signs in with a code and PKCE S256; its secret travels in a header.', [
                'client_name' => 'Forged: everything in the open',
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => ['profile', 'email'],
                'response_mode' => 'query',
            ]),
            new Preset('form-post', 'Posted response', 'Gets the code in a POST rather than in the URL, and its secret in the body.', [
                'client_name' => 'Forged: a posted response',
                'token_endpoint_auth_method' => 'client_secret_post',
                'scope' => ['profile', 'email'],
                'response_mode' => 'form_post',
            ]),
            new Preset('key', 'Private key', 'Signs an assertion with its own key: no shared secret.', [
                'client_name' => 'Forged: a key instead of a secret',
                'token_endpoint_auth_method' => 'private_key_jwt',
                'scope' => ['profile', 'email'],
                'response_mode' => 'query',
                'frontchannel_logout' => true,
                'backchannel_logout' => true,
                'logout_session_required' => true,
            ]),
            new Preset('rar', 'Authorization details', 'Asks to pay one invoice up to 45 EUR, rather than for a scope.', [
                'client_name' => 'Forged: what it may do',
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => ['profile', 'invoices.read'],
                'response_mode' => 'query',
                'authorization_details_type' => 'invoice_payment',
                'authorization_details' => $this->invoicePayment(),
            ]),
            new Preset('fapi', 'FAPI 2.0 with DPoP', 'Pushes a signed request, reads a signed response, holds a token bound to its key.', [
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
            new Preset('fapi-mtls', 'FAPI 2.0 with mTLS', 'The same profile, proven by the certificate of the connection.', [
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
            new Preset('pairwise', 'Pairwise subject', 'Sees the user under an identifier no other client sees.', [
                'client_name' => 'Forged: a sub of its own',
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => ['profile', 'email'],
                'response_mode' => 'query',
                'subject_type' => 'pairwise',
                'id_token_encrypted_response_alg' => 'RSA-OAEP-256',
            ]),
            new Preset('public', 'Public client', 'Holds no secret at all: PKCE alone ties the code to it.', [
                'client_name' => 'Forged: no credential at all',
                'token_endpoint_auth_method' => 'none',
                'scope' => ['profile'],
                'response_mode' => 'query',
            ]),
            new Preset('jarm', 'Signed response', 'Gets the answer as a JWT it verifies (JARM).', [
                'client_name' => 'Forged: a signed response',
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => ['profile', 'email'],
                'response_mode' => 'jwt',
                'authorization_signed_response_alg' => 'ES256',
            ]),
            new Preset('par', 'Pushed request', 'Pushes its request first; the browser carries only a reference (PAR).', [
                'client_name' => 'Forged: a pushed request',
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => ['profile', 'email'],
                'response_mode' => 'query',
                'pushed' => true,
                'require_pushed_authorization_requests' => true,
            ]),
            new Preset('jar', 'Signed request', 'Sends its request signed with its own key (JAR).', [
                'client_name' => 'Forged: a signed request',
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => ['profile', 'email'],
                'response_mode' => 'query',
                'request_object_signing_alg' => 'ES256',
                'require_signed_request_object' => true,
            ]),
            new Preset('secret-jwt', 'Secret-signed assertion', 'Signs an assertion with its secret instead of sending the secret.', [
                'client_name' => 'Forged: an assertion signed with the secret',
                'token_endpoint_auth_method' => 'client_secret_jwt',
                'scope' => ['profile', 'email'],
                'response_mode' => 'query',
            ]),
            new Preset('tls', 'PKI certificate', 'Proves who it is with a certificate an authority issued (mTLS).', [
                'client_name' => 'Forged: a certificate of an authority',
                'token_endpoint_auth_method' => 'tls_client_auth',
                'scope' => ['profile', 'email'],
                'response_mode' => 'query',
            ]),
            new Preset('self-signed', 'Self-signed certificate', 'Proves who it is with a certificate it published itself (mTLS).', [
                'client_name' => 'Forged: a self-signed certificate',
                'token_endpoint_auth_method' => 'self_signed_tls_client_auth',
                'scope' => ['profile', 'email'],
                'response_mode' => 'query',
            ]),
            new Preset('dpop', 'Bound to a key', 'Holds a token useless without its key: every call carries a proof (DPoP).', [
                'client_name' => 'Forged: a token bound to a key',
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => ['profile', 'email'],
                'response_mode' => 'query',
                'token_binding' => 'dpop',
                'dpop_signing_alg' => 'ES256',
            ]),
            new Preset('mtls-bound', 'Bound to a certificate', 'Holds a token useless without its certificate.', [
                'client_name' => 'Forged: a token bound to a certificate',
                'token_endpoint_auth_method' => 'self_signed_tls_client_auth',
                'scope' => ['profile', 'email'],
                'response_mode' => 'query',
                'token_binding' => 'mtls',
                'tls_client_certificate_bound_access_tokens' => true,
            ]),
            new Preset('refresh', 'Refresh token', 'Asks for offline_access and gets a refresh token.', [
                'client_name' => 'Forged: a refresh token',
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => ['profile', 'email', 'offline_access'],
                'response_mode' => 'query',
            ]),
            new Preset('encrypted-id-token', 'Encrypted ID token', 'Gets an ID token only its own key can open.', [
                'client_name' => 'Forged: an encrypted ID token',
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => ['profile', 'email'],
                'response_mode' => 'query',
                'id_token_encrypted_response_alg' => 'RSA-OAEP-256',
            ]),
            new Preset('userinfo-jwt', 'Signed, encrypted UserInfo', 'Gets UserInfo as a JWT, signed by the provider and encrypted to it.', [
                'client_name' => 'Forged: a signed and encrypted UserInfo',
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => ['profile', 'email'],
                'response_mode' => 'query',
                'userinfo_signed_response_alg' => 'ES256',
                'userinfo_encrypted_response_alg' => 'RSA-OAEP-256',
            ]),
            new Preset('frontchannel', 'Front-channel logout', 'Is told of a logout in the browser, by a frame the provider loads.', [
                'client_name' => 'Forged: front-channel logout',
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => ['profile', 'email'],
                'response_mode' => 'query',
                'frontchannel_logout' => true,
                'logout_session_required' => true,
            ]),
            new Preset('backchannel', 'Back-channel logout', 'Is told of a logout server to server, by a signed logout token.', [
                'client_name' => 'Forged: back-channel logout',
                'token_endpoint_auth_method' => 'client_secret_basic',
                'scope' => ['profile', 'email'],
                'response_mode' => 'query',
                'backchannel_logout' => true,
                'logout_session_required' => true,
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
