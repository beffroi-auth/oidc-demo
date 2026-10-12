<?php

declare(strict_types=1);

namespace App\Forge;

use App\Forge\Flow\Jwt;
use Symfony\Contracts\Cache\CacheInterface;
use Symfony\Contracts\Cache\ItemInterface;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * What the provider offers, read from the document it publishes (RFC 8414 §3, OIDC Discovery §3) and from
 * nowhere else: the form of the forge offers what this says and refuses the rest, so that a choice nobody
 * announced cannot be composed in the first place.
 *
 * It is the same rule the provider holds itself to, from the other side: its document is derived from what
 * it is wired with, so a form derived from its document offers what is wired. Two lists that must agree
 * are one list.
 *
 * The one thing the form offers that no document announces is the kinds of token binding, which are what
 * the client does with what it was issued rather than something the provider lists. What the provider
 * announces and does not offer a client is the other way round: the shape of the access token, the
 * resources, and four members more are written by a declaration or by the registration policy of the
 * tenant, and a client that asks for one is refused (decision 0009, RegisteredMembers of the provider).
 */
final readonly class Offer
{
    /**
     * How a client holds what it was issued: as a bearer token, bound to a key it proves at every request
     * (RFC 9449), or bound to the certificate it presents (RFC 8705 §3).
     */
    public const array TOKEN_BINDINGS = ['none', 'dpop', 'mtls'];

    public function __construct(
        private HttpClientInterface $httpClient,
        private CacheInterface $cache,
        private string $providerUri,
    ) {
    }

    /**
     * The algorithms a document of this provider may be encrypted to a client of the forge with: what it
     * announces for that document, held to what this application can open (Jwt::OPENS). An algorithm it
     * announces that nothing here opens is a gap and not a choice, so it is offered nowhere and refused
     * wherever a composition names it.
     *
     * @return list<string>
     */
    public function keyEncryptionAlgorithms(string $prefix): array
    {
        return array_values(array_intersect($this->names($prefix . '_encryption_alg_values_supported'), Jwt::OPENS));
    }

    /**
     * The same for what the payload of such a document is encrypted with.
     *
     * @return list<string>
     */
    public function contentEncryptionAlgorithms(string $prefix): array
    {
        return array_values(array_intersect($this->names($prefix . '_encryption_enc_values_supported'), Jwt::PAYLOADS));
    }

    /**
     * @return array<string, mixed>
     */
    public function document(): array
    {
        /** @var array<string, mixed> $document */
        $document = $this->cache->get('forge.document.' . hash('xxh128', $this->providerUri), function (ItemInterface $item, bool &$save): array {
            $item->expiresAfter(3600);

            try {
                $response = $this->httpClient->request('GET', $this->providerUri . '/.well-known/openid-configuration', [
                    'max_redirects' => 0,
                ]);
                $values = $response->getStatusCode() === 200 ? json_decode($response->getContent(false), true) : null;
            } catch (TransportExceptionInterface) {
                $values = null;
            }

            if (is_array($values)) {
                return $values;
            }

            // A provider that could not be read is one to read again at the next request, and never one
            // that offers nothing for the hour a document is kept: an empty document has the shape of a
            // provider that announces nothing, so keeping one makes this page say of the provider what
            // the network did.
            $save = false;

            return [];
        });

        return $document;
    }

    public function issuer(): string
    {
        $issuer = $this->document()['issuer'] ?? null;

        return is_string($issuer) && $issuer !== '' ? $issuer : $this->providerUri;
    }

    public function isReachable(): bool
    {
        return is_string($this->document()['issuer'] ?? null);
    }

    /**
     * @throws ForgeException when the provider announces no such endpoint
     */
    public function endpoint(string $name): string
    {
        $endpoint = $this->document()[$name] ?? null;
        if (! is_string($endpoint) || $endpoint === '') {
            throw new ForgeException(sprintf('The provider announces no "%s".', $name));
        }

        return $endpoint;
    }

    /**
     * RFC 8705 §5: the endpoints of the provider that ask for a client certificate, which a client bound
     * to one uses in place of the ordinary ones, and an empty list for a provider that serves none.
     *
     * @return array<string, string>
     */
    public function mutualTlsEndpoints(): array
    {
        $aliases = $this->document()['mtls_endpoint_aliases'] ?? null;

        return is_array($aliases) ? array_filter($aliases, is_string(...)) : [];
    }

    /**
     * An endpoint of the provider as a client bound to a certificate reaches it: the alias when there is
     * one for that endpoint, the ordinary one otherwise (RFC 8705 §5).
     *
     * @throws ForgeException when the provider announces neither
     */
    public function mutualTlsEndpoint(string $name): string
    {
        return $this->mutualTlsEndpoints()[$name] ?? $this->endpoint($name);
    }

    /**
     * What the document says of a list it announces, the names in the order the provider wrote them.
     *
     * @return list<string>
     */
    public function names(string $member): array
    {
        $values = $this->document()[$member] ?? null;

        return is_array($values) ? array_values(array_filter($values, is_string(...))) : [];
    }

    public function says(string $member): bool
    {
        return ($this->document()[$member] ?? null) === true;
    }

    /**
     * The scopes a client of the forge may ask for. "openid" is in every composition, this being a client
     * that signs a user in, so it is not offered as a choice: it is added wherever a composition is read.
     *
     * @return list<string>
     */
    public function scopes(): array
    {
        return array_values(array_filter($this->names('scopes_supported'), static fn (string $scope): bool => $scope !== 'openid'));
    }
}
