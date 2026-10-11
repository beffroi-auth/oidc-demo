<?php

declare(strict_types=1);

namespace App\Forge;

use App\Forge\Flow\Authentication\ClientAuthentications;
use App\Forge\Flow\Authentication\PresentsACertificateInterface;
use App\Forge\Flow\Authentication\PublishesAKeyInterface;
use Psr\Clock\ClockInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * What builds a client at the provider out of a composition (RFC 7591 §3), and what takes it away again
 * (RFC 7592 §2.3).
 *
 * The provider is asked for nothing it does not offer every client: the registration carries the members
 * of the composition, the public half of what the forge drew, and the URIs of the routes of that client,
 * and it is authorised the way decision 0009 calls controlled by initial token, a credential the console
 * of the tenant issued and that `castor demo` hands to this demonstration. A provider whose tenant
 * registers no client this way answers the refusal, and the page shows that answer rather than hiding it.
 *
 * Building under a handle that already holds a client replaces it: the one that was there is deleted at
 * the provider first, so a preset built twice leaves one registration and not two.
 */
final readonly class Forge
{
    public function __construct(
        private HttpClientInterface $httpClient,
        private Offer $offer,
        private BuiltClients $clients,
        private ClientAuthentications $methods,
        private UrlGeneratorInterface $urls,
        private ClockInterface $clock,
        private string $initialAccessToken,
    ) {
    }

    /**
     * RFC 7591 §1.2: the credential the registration endpoint asks for in the mode a real ecosystem uses.
     * A demonstration that holds none says so on the page instead of registering nothing.
     */
    public function holdsAnInitialAccessToken(): bool
    {
        return $this->initialAccessToken !== '';
    }

    /**
     * @param array<string, mixed> $form what the page submitted
     *
     * @throws ForgeException when the composition is not offered, the material cannot be drawn, or the
     *                        provider refuses the registration
     */
    public function build(array $form, ?string $handle = null): BuiltClient
    {
        $composition = Composition::read($form, $this->offer);
        $method = $this->methods->named($composition->credentials->method);
        $handle ??= 'own-' . bin2hex(random_bytes(3));

        $material = Material::drawnFor(
            $composition,
            $method instanceof PublishesAKeyInterface,
            $method instanceof PresentsACertificateInterface,
            $handle,
        );

        $registration = [
            ...$composition->registration(
                [$this->uri('app_forge_callback', $handle)],
                $this->uri('app_home'),
                $this->uri('app_forge_frontchannel_logout', $handle),
                $this->uri('app_forge_backchannel_logout', $handle),
            ),
            ...($method instanceof PresentsACertificateInterface ? $method->registration($material->subjectName) : []),
        ];
        $published = $material->publishedKeys();
        if ($published !== null) {
            $registration['jwks'] = $published;
        }

        // the handle names one registration at a time: what was there is taken away before what replaces
        // it exists, so that a client nobody can reach is never left behind at the provider
        if ($this->clients->holds($handle)) {
            $this->unmake($this->clients->of($handle));
        }

        $answer = $this->register($registration);
        $clientId = $answer['client_id'] ?? null;
        if (! is_string($clientId) || $clientId === '') {
            throw new ForgeException(sprintf('The provider registered no client: %s', json_encode($answer)));
        }
        $secret = $answer['client_secret'] ?? null;

        $client = new BuiltClient(
            $handle,
            $clientId,
            is_string($secret) && $secret !== '' ? $secret : null,
            $form,
            $registration,
            $this->withoutCredentials($answer),
            $material,
            $this->clock->now()->getTimestamp(),
        );
        $this->clients->keep($client);

        return $client;
    }

    /**
     * RFC 7592 §2.1: what the provider says of this client now, read at the URI it handed out with the
     * credential it handed out, which is the one way a dynamic client reads its own registration.
     *
     * @return array<string, mixed>
     *
     * @throws ForgeException when the provider handed out neither, or answers something else
     */
    public function read(BuiltClient $client): array
    {
        $response = $this->httpClient->request('GET', $this->registrationUri($client), [
            'max_redirects' => 0,
            'auth_bearer' => $this->registrationAccessToken($client),
        ]);
        $values = json_decode($response->getContent(false), true);
        if (! is_array($values)) {
            throw new ForgeException(sprintf('Reading the registration answered %d, which is no JSON object.', $response->getStatusCode()));
        }

        /** @var array<string, mixed> $values */
        return $this->withoutCredentials($values);
    }

    /**
     * RFC 7592 §2.3: the client deletes itself. What the provider answers is 204 and nothing, and the
     * store forgets it whatever the provider answered: a client this demonstration cannot reach any more
     * is not one it should keep offering a page for, and the provider removes an unused registration on
     * its own (decision 0009).
     */
    public function unmake(BuiltClient $client): void
    {
        $uri = $client->registrationUri();
        $token = $client->registrationAccessToken();
        try {
            if ($uri !== null && $token !== null) {
                $this->httpClient->request('DELETE', $uri, [
                    'max_redirects' => 0,
                    'auth_bearer' => $token,
                ])->getStatusCode();
            }
        } finally {
            $this->clients->forget($client->handle);
        }
    }

    /**
     * @param array<string, mixed> $registration
     *
     * @return array<string, mixed>
     *
     * @throws ForgeException when the provider refuses it
     */
    private function register(array $registration): array
    {
        $options = [
            'max_redirects' => 0,
            'json' => $registration,
        ];
        if ($this->holdsAnInitialAccessToken()) {
            $options['auth_bearer'] = $this->initialAccessToken;
        }

        $response = $this->httpClient->request('POST', $this->offer->endpoint('registration_endpoint'), $options);
        $body = $response->getContent(false);
        $values = json_decode($body, true);
        if (! is_array($values)) {
            throw new ForgeException(sprintf('The registration endpoint answered %d: %s', $response->getStatusCode(), $body));
        }
        if ($response->getStatusCode() !== 201) {
            throw new ForgeException(sprintf(
                'The provider refused this composition (%d %s): %s',
                $response->getStatusCode(),
                $values['error'] ?? '',
                $values['error_description'] ?? $body,
            ));
        }

        /** @var array<string, mixed> $values */
        return $values;
    }

    /**
     * What the page of a built client may print: everything the provider answered but the two credentials
     * it issued, which the client holds and nothing shows.
     *
     * @param array<string, mixed> $answer
     *
     * @return array<string, mixed>
     */
    private function withoutCredentials(array $answer): array
    {
        unset($answer['client_secret'], $answer['registration_access_token']);

        return $answer;
    }

    /**
     * @throws ForgeException when the provider handed out no URI for this client
     */
    private function registrationUri(BuiltClient $client): string
    {
        return $client->registrationUri() ?? throw new ForgeException(
            'The provider handed this client no registration URI, so it reads nothing of itself (RFC 7592 §2).',
        );
    }

    /**
     * @throws ForgeException when the provider handed out no credential for this client
     */
    private function registrationAccessToken(BuiltClient $client): string
    {
        return $client->registrationAccessToken() ?? throw new ForgeException(
            'The provider handed this client no registration access token, so it reads nothing of itself (RFC 7592 §2).',
        );
    }

    private function uri(string $route, ?string $handle = null): string
    {
        return $this->urls->generate(
            $route,
            $handle === null ? [] : ['handle' => $handle],
            UrlGeneratorInterface::ABSOLUTE_URL,
        );
    }
}
