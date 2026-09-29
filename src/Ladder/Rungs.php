<?php

declare(strict_types=1);

namespace App\Ladder;

/**
 * The ladder of demonstration clients (heidi#201), from the plainest client to the whole of FAPI 2.0.
 *
 * One rung is one registration on the provider and one firewall here. A rung adds one thing to the one
 * before it, and what it adds is what the provider grew during the spike: how the client authenticates,
 * which way the authorization response comes back, what shape its access token has, and what a logout
 * reaches. Nothing of the provider changes from one rung to the next: what changes is what the client
 * registered and what it asks for.
 */
final class Rungs
{
    /**
     * @var array<string, array{name: string, firewall: string, client: string, adds: string, capabilities: array<string, string>}>
     */
    public const RUNGS = [
        'basic' => [
            'name' => 'Basic',
            'firewall' => 'ladder_basic',
            'client' => 'oidc-demo',
            'adds' => 'The starting point: everything goes through the address bar of the browser.',
            'capabilities' => [
                'Client authentication' => 'client_secret_basic, the secret in the HTTP Basic header',
                'Authorization request' => 'in clear in the query, with PKCE S256',
                'Authorization response' => 'code, state and iss in the query (RFC 9207)',
                'Tokens' => 'a signed at+jwt, verified offline against the JWK Set',
                'Logout' => 'RP-Initiated Logout, a round trip through the browser',
            ],
        ],
        'opaque' => [
            'name' => 'Opaque token',
            'firewall' => 'ladder_opaque',
            'client' => 'oidc-demo-opaque',
            'adds' => 'The same client, an access token that says nothing to whoever reads it.',
            'capabilities' => [
                'Client authentication' => 'client_secret_basic',
                'Authorization request' => 'in clear in the query, with PKCE S256',
                'Authorization response' => 'code, state and iss in the query',
                'Tokens' => 'an opaque access token: a resource server asks the provider what it is (RFC 7662), on every request',
                'Logout' => 'RP-Initiated Logout',
            ],
        ],
        'form-post' => [
            'name' => 'Posted response',
            'firewall' => 'ladder_form_post',
            'client' => 'demo-form-post',
            'adds' => 'The response no longer travels in the URL: the provider posts it.',
            'capabilities' => [
                'Client authentication' => 'client_secret_post, the secret in the body',
                'Authorization request' => 'in clear in the query, with PKCE S256',
                'Authorization response' => 'form_post: a self-submitting page, nothing in the browser history nor in the logs',
                'Tokens' => 'a signed at+jwt',
                'Logout' => 'RP-Initiated Logout',
            ],
        ],
        'key' => [
            'name' => 'Key of the client',
            'firewall' => 'ladder_key',
            'client' => 'demo-key',
            'adds' => 'The client shares no secret any more: it proves a key, and it is told of logouts.',
            'capabilities' => [
                'Client authentication' => 'private_key_jwt: an assertion signed with ES256 (RFC 7523)',
                'Authorization request' => 'in clear in the query, with PKCE S256',
                'Authorization response' => 'code, state and iss in the query',
                'Tokens' => 'a signed at+jwt',
                'Logout' => 'RP-Initiated Logout, and the front channel: the logout page of the provider loads a URI of this client in a frame (Front-Channel Logout 1.0)',
            ],
        ],
        'rar' => [
            'name' => 'What it asks for',
            'firewall' => 'ladder_rar',
            'client' => 'demo-rar',
            'adds' => 'The client no longer asks for a kind of thing: it asks what it may do, to what, and up to how much.',
            'capabilities' => [
                'Client authentication' => 'client_secret_basic',
                'Authorization request' => 'in clear in the query, with PKCE S256, and an authorization_details (RFC 9396) that oidc_login sends through authorization_params',
                'Consent' => 'the page of the provider says the detail in words, in the language of the reader: the invoice named, what may be done to it, and the most that may be moved',
                'Authorization response' => 'code, state and iss in the query',
                'Tokens' => 'an at+jwt carrying authorization_details as the type of the detail built it; the token endpoint response says what it granted, and introspection gives it back',
                'Logout' => 'RP-Initiated Logout',
            ],
        ],
        'fapi' => [
            'name' => 'FAPI 2.0',
            'firewall' => 'ladder_fapi',
            'client' => 'demo-fapi',
            'adds' => 'Nothing travels through the browser in clear any more: the request is pushed and signed, the response is signed, the token is bound to a key, and the documents are encrypted to this client.',
            'capabilities' => [
                'Client authentication' => 'private_key_jwt (RFC 7523)',
                'Authorization request' => 'pushed to the /par endpoint (RFC 9126) and signed as a request object (RFC 9101): the browser carries client_id and request_uri and nothing else',
                'Authorization response' => 'JARM: a single "response" parameter, a JWT signed by the provider',
                'Tokens' => 'an at+jwt bound by DPoP (RFC 9449): cnf.jkt, and a proof signed for every request; ID token and UserInfo signed then encrypted to the key of this client',
                'Logout' => 'RP-Initiated Logout and the front channel',
            ],
        ],
    ];

    /**
     * @return array{name: string, firewall: string, client: string, adds: string, capabilities: array<string, string>}
     */
    public static function of(string $slug): array
    {
        return self::RUNGS[$slug] ?? throw new \InvalidArgumentException(sprintf('No rung "%s" on the ladder.', $slug));
    }

    /**
     * The slugs, as a route requirement writes them.
     */
    public static function pattern(): string
    {
        return implode('|', array_keys(self::RUNGS));
    }
}
