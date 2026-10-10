<?php

namespace App\Api;

use Symfony\Contracts\HttpClient\HttpClientInterface;
use Symfony\Contracts\HttpClient\ResponseInterface;
use Symfony\Contracts\HttpClient\ResponseStreamInterface;

/**
 * How this API asks the provider about an access token (RFC 7662 section 2.1), and the one thing in it that
 * belongs to a demonstration rather than to a resource server.
 *
 * A resource server has one identity: it introspects as the client its tokens are issued to, because the
 * provider describes a token to that client and to no other (RFC 7662 section 2.2, and the provider of
 * this demonstration applies it). This application is not one client: it signs a user in on its main
 * firewall and on every rung of the ladder under /c/, each a client of its own, so whoever reads a page of
 * it holds a token of whichever client that page belongs to. Asking as one of them would answer 401 to a
 * token the demonstration itself had just handed out, which is what this class exists to avoid: the
 * endpoint is asked as each client whose secret this application holds, and the first answer that describes
 * the token is the one the firewall reads.
 *
 * The clients whose secret it does not hold are the two rungs that prove a key instead of sharing a secret
 * (private_key_jwt): their tokens stay refused here, because introspecting them would mean signing an
 * assertion, which is not what an HTTP client does. They are named in config/services.yaml.
 *
 * What a token costs is one request per client until it is described, and nothing until it expires: the
 * firewall remembers the answer for the few seconds of app.api.introspection_cache_ttl, whichever client
 * gave it.
 */
final readonly class WhicheverClientKnowsTheToken implements HttpClientInterface
{
    /**
     * @param HttpClientInterface               $client  the scoped client of the introspection endpoint,
     *                                                   whose credentials this one replaces at each attempt
     * @param list<array{client_id: string, secret: string}> $clients the clients of the demonstration, in the
     *                                                   order they are asked
     */
    public function __construct(
        private HttpClientInterface $client,
        private array $clients,
    ) {
    }

    public function request(string $method, string $url, array $options = []): ResponseInterface
    {
        $answered = null;

        foreach ($this->clients as $client) {
            if ('' === $client['client_id'] || '' === $client['secret']) {
                continue;
            }

            $response = $this->client->request($method, $url, [
                ...$options,
                'auth_basic' => [$client['client_id'], $client['secret']],
            ]);

            if (self::describesTheToken($response)) {
                return $response;
            }

            $answered = $response;
        }

        // every client was asked and none was answered anything about that token: the last answer is what
        // the firewall reads, so what it reports is what the provider said rather than something made up here
        return $answered ?? $this->client->request($method, $url, $options);
    }

    public function stream(ResponseInterface|iterable $responses, ?float $timeout = null): ResponseStreamInterface
    {
        return $this->client->stream($responses, $timeout);
    }

    public function withOptions(array $options): static
    {
        return new self($this->client->withOptions($options), $this->clients);
    }

    /**
     * RFC 7662 section 2.2: a provider that will not describe the token to the client that asked answers
     * "active": false, exactly as it does for a token that expired or was never issued. A client whose
     * credentials the provider refuses is answered an error, which is not an answer about the token either.
     */
    private static function describesTheToken(ResponseInterface $response): bool
    {
        try {
            return true === ($response->toArray(false)['active'] ?? false);
        } catch (\Throwable) {
            return false;
        }
    }
}
