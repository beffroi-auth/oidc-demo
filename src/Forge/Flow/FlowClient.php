<?php

declare(strict_types=1);

namespace App\Forge\Flow;

use App\Forge\BuiltClient;
use App\Forge\Composition;
use App\Forge\Flow\Authentication\ClientAuthenticationInterface;
use App\Forge\Flow\Authentication\ClientAuthentications;
use App\Forge\Flow\Authentication\PresentsACertificateInterface;
use App\Forge\Flow\Binding\Bindings;
use App\Forge\Flow\Binding\TokenBindingInterface;
use App\Forge\Flow\Delivery\AuthorizationResponseInterface;
use App\Forge\Flow\Delivery\Deliveries;
use App\Forge\ForgeException;
use App\Forge\Offer;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * The client of the forge: one authorization code flow, played exactly as the composition of a built
 * client says to, and recording every hop as it happens.
 *
 * It holds no case for a kind of anything. How the client authenticates, how the answer comes back and
 * what the token is bound to are three classes it is handed, and what it does itself is the flow all
 * three are part of: the request (pushed or not, signed or not), the answer, the exchange, the ID token
 * and the UserInfo answer.
 *
 * It is laboratory code, and it closes no gap of Symfony's own authenticator: `RP-04`, `RP-05`, `RP-06`
 * and `RP-16` of the status document are what `oidc_login` cannot do, and they stay open whatever is
 * written here. The provider is bent for none of it, every request below being what it serves to any
 * client registered the same way.
 */
final readonly class FlowClient
{
    private const string REQUEST_OBJECT_TYPE = 'oauth-authz-req+jwt';

    public function __construct(
        private HttpClientInterface $httpClient,
        private Offer $offer,
        private Jwt $jwt,
        private ClientAuthentications $authentications,
        private Deliveries $deliveries,
        private Bindings $bindings,
    ) {
    }

    /**
     * The composition this client was built from, read back from the form it was composed with so that
     * the flow and the registration cannot disagree about it.
     *
     * @throws ForgeException when the provider stopped offering something it holds
     */
    public function compositionOf(BuiltClient $client): Composition
    {
        return Composition::read($client->form, $this->offer);
    }

    public function deliveryOf(Composition $composition): AuthorizationResponseInterface
    {
        return $this->deliveries->forMode($composition->request->responseMode);
    }

    /**
     * What a composition is, in words, one line per family: the sentence of each capability comes from the
     * class that plays it, so the page of a built client says what the demonstration will actually do and
     * never a sentence written beside it.
     *
     * @return array<string, string>
     */
    public function describe(Composition $composition): array
    {
        $method = $this->authentications->named($composition->credentials->method);
        $binding = $this->bindings->named($composition->tokens->binding);
        $request = $composition->request;

        return [
            'What it asks for' => sprintf(
                'the scopes %s%s',
                implode(', ', $composition->asksFor->scopes),
                $composition->asksFor->authorizationDetailsType === null
                    ? ''
                    : sprintf(', and an authorization_details of the type "%s" (RFC 9396 §2)', $composition->asksFor->authorizationDetailsType),
            ),
            'Client authentication' => $method->describe(),
            'Authorization request' => implode(', ', array_filter([
                $request->pushed
                    ? 'pushed to the provider, the browser carrying a client identifier and a URI (RFC 9126 §2)'
                    : 'in the URL of the browser',
                $request->isSignedAsARequestObject()
                    ? sprintf('signed as a request object with %s (RFC 9101 §4)', $request->requestObjectSigningAlgorithm)
                    : 'not signed',
                'PKCE S256 (RFC 7636 §4.3)',
                $request->acrValues === null ? null : sprintf('asking for acr_values %s', $request->acrValues),
                $request->prompt === null ? null : sprintf('with prompt=%s', $request->prompt),
            ], static fn (?string $part): bool => $part !== null)),
            'Authorization response' => sprintf(
                '%s%s',
                $this->deliveryOf($composition)->describe(),
                $composition->documents->authorizationResponse->isEncrypted()
                    ? sprintf(', encrypted %s / %s to this client (JARM §4.2)', $composition->documents->authorizationResponse->keyEncryption, $composition->documents->authorizationResponse->contentEncryption)
                    : '',
            ),
            'Access token' => sprintf(
                '%s. What shape it takes is the tenant\'s and not this client\'s to ask for (decision 0009)',
                $binding->describe(),
            ),
            'ID token' => $composition->documents->idToken->describe('signed with what the provider signs with'),
            'UserInfo' => $composition->documents->userInfo->describe('plain JSON'),
            'Its subject' => $composition->subjectType === 'pairwise'
                ? 'pairwise: an identifier this client alone sees, the same user being somebody else to every other sector (OIDC Core §8.1)'
                : 'public: the same identifier every client of this provider sees (OIDC Core §8)',
            'What a logout reaches' => implode(', ', array_filter([
                'RP-Initiated Logout, a round trip through the browser',
                $composition->logout->frontChannel ? 'the front channel: a URI of this client loaded in a frame of the logout page (Front-Channel Logout 1.0 §3)' : null,
                $composition->logout->backChannel ? 'the back channel: a logout token posted to this client wherever the session ended (Back-Channel Logout 1.0 §2.5)' : null,
            ], static fn (?string $part): bool => $part !== null)),
        ];
    }

    /**
     * OIDC Core §3.1.2.1, RFC 7636 §4.1, RFC 9126 §2 and RFC 9101 §4: the request this client makes, in
     * the shape it composed. What the browser then carries is everything, or a client identifier and a
     * URI, or everything inside one signature.
     *
     * @throws ForgeException when the request cannot be made
     */
    public function start(BuiltClient $client): StartedFlow
    {
        $composition = $this->compositionOf($client);
        $binding = $this->bindings->named($composition->tokens->binding);
        $redirectUri = $this->redirectUriOf($client);

        $verifier = self::random();
        $state = self::random();
        $nonce = self::random();
        $remembered = [
            'state' => $state,
            'nonce' => $nonce,
            'verifier' => $verifier,
            ...$binding->remember($composition->tokens->dpopSigningAlgorithm),
        ];

        $parameters = [
            'response_type' => 'code',
            'client_id' => $client->clientId,
            'redirect_uri' => $redirectUri,
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => self::base64Url(hash('sha256', $verifier, true)),
            'code_challenge_method' => 'S256',
            'response_mode' => $composition->request->responseMode,
            ...$composition->parameters(),
        ];

        $hops = [];
        $requestObject = null;
        if ($composition->request->isSignedAsARequestObject()) {
            $requestObject = $this->requestObject($client, $parameters);
            $hops[] = new Hop(
                'Signed request object (RFC 9101 §4)',
                sprintf(
                    '%s, %d characters, holding the %d parameters of the request',
                    $client->material->signingAlgorithm ?? '?',
                    strlen($requestObject),
                    count($parameters),
                ),
                $requestObject,
            );
        }

        if ($composition->request->pushed) {
            $pushed = $this->push($client, $composition, $parameters, $requestObject, $remembered);
            $hops[] = new Hop(
                'Pushed authorization request (RFC 9126 §2)',
                sprintf('request_uri %s, good for %d seconds, and nothing of the request in the browser', $pushed['request_uri'], $pushed['expires_in']),
                (string) json_encode($pushed, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES),
            );
            $carried = [
                'client_id' => $client->clientId,
                'request_uri' => $pushed['request_uri'],
            ];
        } elseif ($requestObject !== null) {
            // RFC 9101 §4: the request travels in the browser as one signature, the client identifier
            // beside it being what tells the provider whose key to read it with
            $carried = [
                'client_id' => $client->clientId,
                'request' => $requestObject,
            ];
        } else {
            $carried = $parameters;
        }

        $url = $this->offer->endpoint('authorization_endpoint') . '?' . http_build_query($carried, '', '&', \PHP_QUERY_RFC3986);
        $hops[] = new Hop(
            'To the authorization endpoint',
            sprintf('%d parameters in the URL of the browser: %s', count($carried), implode(', ', array_keys($carried))),
            $url,
        );

        return new StartedFlow($url, [
            ...$remembered,
            'hops' => array_map(static fn (Hop $hop): array => $hop->toArray(), $hops),
        ]);
    }

    /**
     * The answer, the exchange and the two documents: what the provider sent back, read in the shape this
     * client registered, and the identity it ends up knowing the user by.
     *
     * @param array<string, mixed> $remembered what start() left for this request
     *
     * @throws ForgeException when any step of it does not hold
     */
    public function finish(BuiltClient $client, Request $request, array $remembered): ObtainedIdentity
    {
        $composition = $this->compositionOf($client);
        $method = $this->authentications->named($composition->credentials->method);
        $binding = $this->bindings->named($composition->tokens->binding);
        $delivery = $this->deliveryOf($composition);

        /** @var list<array{label: string, what: string, payload: string|null}> $hops */
        $hops = is_array($remembered['hops'] ?? null) ? $remembered['hops'] : [];

        $answer = $delivery->read($request, $client);
        $parameters = $answer['parameters'];
        $hops[] = (new Hop('Back from the authorization endpoint', $answer['carried'], $answer['payload']))->toArray();

        if (is_string($parameters['error'] ?? null)) {
            throw new ForgeException(sprintf(
                'The provider refused the authorization request: %s (%s).',
                $parameters['error'],
                is_string($parameters['error_description'] ?? null) ? $parameters['error_description'] : 'no description',
            ));
        }
        if (! hash_equals((string) ($remembered['state'] ?? ''), (string) ($parameters['state'] ?? ''))) {
            throw new ForgeException('The answer does not carry the state of this browser (RFC 6749 §10.12).');
        }
        // RFC 9207 §2: the issuer travels beside an answer that is not signed; a signed one names it
        // inside the signature, which the shape that reads it has already checked
        if (! $delivery->isSigned() && ($parameters['iss'] ?? null) !== $this->offer->issuer()) {
            throw new ForgeException('The answer does not name the issuer it came from (RFC 9207 §2).');
        }
        $code = $parameters['code'] ?? null;
        if (! is_string($code) || $code === '') {
            throw new ForgeException('The answer carries no authorization code.');
        }

        $tokens = $this->exchange($client, $composition, $method, $binding, $code, (string) ($remembered['verifier'] ?? ''), $remembered);
        $hops[] = (new Hop(
            'The token endpoint',
            sprintf(
                '%s, token_type %s, %s, expires_in %s',
                $method->describe(),
                is_string($tokens['token_type'] ?? null) ? $tokens['token_type'] : '?',
                self::shapeOf($tokens),
                is_int($tokens['expires_in'] ?? null) ? (string) $tokens['expires_in'] : '?',
            ),
            (string) json_encode(self::withoutTheTokens($tokens), \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES),
        ))->toArray();

        $idToken = $this->readIdToken($client, (string) ($tokens['id_token'] ?? ''), (string) ($remembered['nonce'] ?? ''));
        $hops[] = (new Hop('The ID token (OIDC Core §3.1.3.7)', $idToken['how'], (string) json_encode($idToken['claims'], \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES)))->toArray();

        $subject = (string) ($idToken['claims']['sub'] ?? '');
        if ($subject === '') {
            throw new ForgeException('The ID token names no subject (OIDC Core §2).');
        }

        $userInfo = $this->readUserInfo($client, $composition, $binding, (string) ($tokens['access_token'] ?? ''), $remembered);
        if (! hash_equals($subject, (string) ($userInfo['claims']['sub'] ?? ''))) {
            throw new ForgeException('The "sub" of UserInfo is not the one of the ID token (OIDC Core §5.3.2).');
        }
        $hops[] = (new Hop('UserInfo (OIDC Core §5.3.2)', $userInfo['how'], (string) json_encode($userInfo['claims'], \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES)))->toArray();

        $confirmation = $binding->confirmation($remembered, $client);
        if ($confirmation !== null) {
            $hops[] = (new Hop('What the token is bound to', sprintf('%s, and the provider says %s', $confirmation, self::confirmationOf($tokens)), null))->toArray();
        }

        return new ObtainedIdentity(
            $subject,
            [...$userInfo['claims'], ...$idToken['claims'], 'sub' => $subject],
            [
                'id_token' => $tokens['id_token'] ?? null,
                'access_token' => $tokens['access_token'] ?? null,
                'refresh_token' => $tokens['refresh_token'] ?? null,
                'token_type' => $tokens['token_type'] ?? null,
                'scope' => $tokens['scope'] ?? null,
                'authorization_details' => $tokens['authorization_details'] ?? null,
                'id_token_claims' => $idToken['claims'],
                'confirmation' => $confirmation,
            ],
            $hops,
        );
    }

    /**
     * RP-Initiated Logout §2: where the browser is sent to end the session at the provider, the ID token
     * of this login saying which session that is.
     */
    public function endSessionUrl(BuiltClient $client, string $idToken, string $postLogoutRedirectUri): ?string
    {
        $endpoint = $this->offer->document()['end_session_endpoint'] ?? null;
        if (! is_string($endpoint) || $endpoint === '') {
            return null;
        }

        return $endpoint . '?' . http_build_query([
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => $postLogoutRedirectUri,
            'client_id' => $client->clientId,
        ], '', '&', \PHP_QUERY_RFC3986);
    }

    /**
     * RFC 9101 §4: the request as one signature of the client, carrying the claims a request object
     * carries beside the parameters of the request itself.
     *
     * @param array<string, string> $parameters
     *
     * @throws ForgeException when the client holds no key to sign it with
     */
    private function requestObject(BuiltClient $client, array $parameters): string
    {
        return $this->jwt->sign(
            [
                'iss' => $client->clientId,
                'aud' => $this->offer->issuer(),
                'jti' => bin2hex(random_bytes(16)),
                'iat' => $this->jwt->now(),
                'nbf' => $this->jwt->now(),
                'exp' => $this->jwt->now() + Jwt::LIFETIME,
                ...$parameters,
            ],
            $client->material->signingJwk(),
            $client->material->signingAlgorithm ?? 'ES256',
            ['typ' => self::REQUEST_OBJECT_TYPE],
        );
    }

    /**
     * RFC 9126 §2: the request handed to the provider server to server, which answers a URI the browser
     * carries in place of it. A client that signed its request pushes the signature; one that did not
     * pushes the parameters.
     *
     * @param array<string, string> $parameters
     * @param array<string, mixed> $remembered what this login holds already, the key of its proofs among it
     *
     * @return array{request_uri: string, expires_in: int}
     *
     * @throws ForgeException when the provider refuses it
     */
    private function push(BuiltClient $client, Composition $composition, array $parameters, ?string $requestObject, array $remembered): array
    {
        $method = $this->authentications->named($composition->credentials->method);
        $binding = $this->bindings->named($composition->tokens->binding);
        $endpoint = $this->endpoint('pushed_authorization_request_endpoint', $method, $binding);

        $options = [
            'body' => $requestObject === null ? $parameters : [
                'client_id' => $client->clientId,
                'request' => $requestObject,
            ],
        ];
        $options = $method->apply($client, $options);
        // RFC 9449 §10.1: a request pushed by a client that binds its tokens to a key proves that key
        // here too, the proof being made for this request and this URL
        $options = $binding->apply('POST', $endpoint, $options, $remembered, $client);

        $answer = $this->json('POST', $endpoint, $options);
        $requestUri = $answer['request_uri'] ?? null;
        if (! is_string($requestUri) || $requestUri === '') {
            throw new ForgeException(sprintf('The pushed authorization request was refused: %s', json_encode($answer)));
        }

        return [
            'request_uri' => $requestUri,
            'expires_in' => is_int($answer['expires_in'] ?? null) ? $answer['expires_in'] : 0,
        ];
    }

    /**
     * RFC 6749 §4.1.3, RFC 7636 §4.5, RFC 9449 §5: the code exchanged with the verifier of the challenge
     * that was sent, the credential of the client, and whatever its binding has to prove.
     *
     * @param array<string, mixed> $remembered
     *
     * @return array<string, mixed>
     *
     * @throws ForgeException when the provider answers no token
     */
    private function exchange(
        BuiltClient $client,
        Composition $composition,
        ClientAuthenticationInterface $method,
        TokenBindingInterface $binding,
        string $code,
        string $verifier,
        array $remembered,
    ): array {
        $endpoint = $this->endpoint('token_endpoint', $method, $binding);
        $options = [
            'body' => [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->redirectUriOf($client),
                'code_verifier' => $verifier,
            ],
        ];
        $options = $method->apply($client, $options);
        $options = $binding->apply('POST', $endpoint, $options, $remembered, $client);

        $answer = $this->json('POST', $endpoint, $options);
        if (! is_string($answer['access_token'] ?? null) || ! is_string($answer['id_token'] ?? null)) {
            throw new ForgeException(sprintf('The token endpoint answered no token: %s', json_encode($answer)));
        }

        return $answer;
    }

    /**
     * OIDC Core §3.1.3.7: the ID token opened if it was encrypted to this client, verified against the
     * keys of the provider, and checked for what it says of the request it answers.
     *
     * @return array{claims: array<string, mixed>, how: string}
     *
     * @throws ForgeException when it does not hold
     */
    private function readIdToken(BuiltClient $client, string $idToken, string $nonce): array
    {
        if ($idToken === '') {
            throw new ForgeException('The token endpoint answered no ID token (OIDC Core §3.1.3.3).');
        }

        $encryption = null;
        $signed = $idToken;
        if ($this->jwt->isEncrypted($idToken)) {
            $algorithm = is_string($client->registration['id_token_encrypted_response_alg'] ?? null)
                ? $client->registration['id_token_encrypted_response_alg']
                : throw new ForgeException('The provider encrypted the ID token to a client that registered no encryption for it.');
            [$signed, $encryption] = $this->jwt->decrypt($idToken, $client->material->encryptionJwk($algorithm));
        }

        $claims = $this->jwt->verify($signed);
        if (($claims['iss'] ?? null) !== $this->offer->issuer()) {
            throw new ForgeException('The ID token does not name this provider (OIDC Core §3.1.3.7).');
        }
        $audiences = array_filter(is_array($claims['aud'] ?? null) ? $claims['aud'] : [$claims['aud'] ?? null], is_string(...));
        if (! in_array($client->clientId, $audiences, true)) {
            throw new ForgeException('The ID token is not for this client (OIDC Core §3.1.3.7).');
        }
        if (! hash_equals($nonce, (string) ($claims['nonce'] ?? ''))) {
            throw new ForgeException('The ID token does not carry the nonce of this login (OIDC Core §3.1.3.7).');
        }
        $expiresAt = $claims['exp'] ?? null;
        if (! is_int($expiresAt) || $expiresAt <= $this->jwt->now()) {
            throw new ForgeException('The ID token has expired (OIDC Core §3.1.3.7).');
        }

        return [
            'claims' => $claims,
            'how' => $encryption === null
                ? sprintf('signed %s, %d claims', $this->jwt->header($signed)['alg'] ?? '?', count($claims))
                : sprintf('a JWE %s holding a JWS signed %s, %d claims', $encryption, $this->jwt->header($signed)['alg'] ?? '?', count($claims)),
        ];
    }

    /**
     * OIDC Core §5.3.2 and RFC 9449 §7.1: the UserInfo answer, asked for with the access token under the
     * scheme its binding gives it, and read as JSON, as a JWT, or as a JWT inside a JWE, which is what
     * the client registered for it.
     *
     * @param array<string, mixed> $remembered
     *
     * @return array{claims: array<string, mixed>, how: string}
     *
     * @throws ForgeException when the answer does not hold
     */
    private function readUserInfo(BuiltClient $client, Composition $composition, TokenBindingInterface $binding, string $accessToken, array $remembered): array
    {
        $method = $this->authentications->named($composition->credentials->method);
        $endpoint = $this->endpoint('userinfo_endpoint', $method, $binding);
        $options = $binding->apply('GET', $endpoint, [
            'headers' => [
                'Authorization' => sprintf('%s %s', $binding->scheme(), $accessToken),
            ],
            // RFC 8705 §3: a client that authenticates with a certificate receives tokens bound to it
            // whether it registered that or not, so it presents the certificate here as well, where
            // there is no client authentication to carry it
            ...($method instanceof PresentsACertificateInterface ? $method->transport($client) : []),
        ], $remembered, $client, $accessToken);

        $response = $this->httpClient->request('GET', $endpoint, [
            'max_redirects' => 0,
            ...$options,
        ]);
        if ($response->getStatusCode() !== 200) {
            throw new ForgeException(sprintf('UserInfo answered %d: %s', $response->getStatusCode(), $response->getContent(false)));
        }

        $contentType = (string) ($response->getHeaders(false)['content-type'][0] ?? '');
        $body = $response->getContent(false);
        if (! str_contains($contentType, 'jwt')) {
            $claims = json_decode($body, true);

            return [
                'claims' => is_array($claims) ? $claims : [],
                'how' => sprintf('%s, %d claims, not signed', $contentType, is_array($claims) ? count($claims) : 0),
            ];
        }

        $encryption = null;
        $signed = $body;
        if ($this->jwt->isEncrypted($body)) {
            $algorithm = is_string($client->registration['userinfo_encrypted_response_alg'] ?? null)
                ? $client->registration['userinfo_encrypted_response_alg']
                : throw new ForgeException('The provider encrypted the UserInfo answer to a client that registered no encryption for it.');
            [$signed, $encryption] = $this->jwt->decrypt($body, $client->material->encryptionJwk($algorithm));
        }
        $claims = $this->jwt->verify($signed);

        return [
            'claims' => $claims,
            'how' => $encryption === null
                ? sprintf('%s, signed %s, %d claims', $contentType, $this->jwt->header($signed)['alg'] ?? '?', count($claims))
                : sprintf('%s, a JWE %s holding a JWS signed %s, %d claims', $contentType, $encryption, $this->jwt->header($signed)['alg'] ?? '?', count($claims)),
        ];
    }

    /**
     * RFC 8705 §5: the endpoint this client reaches, which is the one that asks for a certificate when it
     * presents one, for its credential or for its binding, and the ordinary one otherwise.
     *
     * @throws ForgeException when the provider announces neither
     */
    private function endpoint(string $name, ClientAuthenticationInterface $method, TokenBindingInterface $binding): string
    {
        return $method instanceof PresentsACertificateInterface || $binding->needsTheCertificateEndpoints()
            ? $this->offer->mutualTlsEndpoint($name)
            : $this->offer->endpoint($name);
    }

    /**
     * The one redirection URI this client registered, which is the route of its handle.
     *
     * @throws ForgeException when its registration carries none
     */
    private function redirectUriOf(BuiltClient $client): string
    {
        $uris = $client->registration['redirect_uris'] ?? null;
        $uri = is_array($uris) ? ($uris[0] ?? null) : null;

        return is_string($uri) ? $uri : throw new ForgeException('This client registered no redirection URI.');
    }

    /**
     * @param array<string, mixed> $options
     *
     * @return array<string, mixed>
     *
     * @throws ForgeException when the answer is no JSON object
     */
    private function json(string $method, string $url, array $options): array
    {
        $response = $this->httpClient->request($method, $url, [
            'max_redirects' => 0,
            ...$options,
        ]);
        $values = json_decode($response->getContent(false), true);
        if (! is_array($values)) {
            throw new ForgeException(sprintf('%s answered %d, which is no JSON object.', $url, $response->getStatusCode()));
        }

        /** @var array<string, mixed> $values */
        return $values;
    }

    /**
     * What the answer of the token endpoint says beside the tokens themselves: a page shows the tokens on
     * their own, so the hop shows what was said about them.
     *
     * @param array<string, mixed> $tokens
     *
     * @return array<string, mixed>
     */
    private static function withoutTheTokens(array $tokens): array
    {
        unset($tokens['access_token'], $tokens['id_token'], $tokens['refresh_token']);

        return $tokens;
    }

    /**
     * What shape the access token came in, read off the token itself: three parts and an "at+jwt" header
     * is the self-contained one (RFC 9068 §2.1), anything else is opaque and says nothing to whoever
     * reads it. It is read and not composed, the shape being the tenant's (decision 0009).
     *
     * @param array<string, mixed> $tokens
     */
    private static function shapeOf(array $tokens): string
    {
        $accessToken = $tokens['access_token'] ?? null;
        $parts = is_string($accessToken) ? explode('.', $accessToken) : [];
        if (count($parts) !== 3) {
            return 'an opaque access token, which a resource server asks the provider about (RFC 7662)';
        }
        $header = json_decode((string) base64_decode(strtr($parts[0], '-_', '+/'), true), true);

        return sprintf(
            'a self-contained access token a resource server verifies offline, typ "%s" (RFC 9068 §2.1)',
            is_array($header) && is_string($header['typ'] ?? null) ? $header['typ'] : '?',
        );
    }

    /**
     * RFC 9449 §6.1 and RFC 8705 §3.1: what the provider says the access token is bound to, read off the
     * token when it is self-contained and from nothing else when it is opaque.
     *
     * @param array<string, mixed> $tokens
     */
    private static function confirmationOf(array $tokens): string
    {
        $accessToken = $tokens['access_token'] ?? null;
        $parts = is_string($accessToken) ? explode('.', $accessToken) : [];
        $claims = count($parts) === 3
            ? json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), true)
            : null;
        $confirmation = is_array($claims) && is_array($claims['cnf'] ?? null) ? $claims['cnf'] : null;

        return $confirmation === null
            ? 'nothing a client can read, the token being opaque'
            : (string) json_encode($confirmation, \JSON_UNESCAPED_SLASHES);
    }

    private static function random(): string
    {
        return bin2hex(random_bytes(32));
    }

    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
