<?php

declare(strict_types=1);

namespace App\Showcase\Grant;

use App\Forge\ForgeException;
use App\Showcase\ClientView;
use App\Showcase\ConfigurationLines;
use App\Showcase\FeatureClientInterface;
use App\Showcase\RegisteredClients;
use App\Showcase\Runs;
use App\Showcase\RunStatus;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 8693: a gateway turns the token of a service into a token that acts on its behalf, the gateway
 * named as the actor (§4.1). The gateway is registered with an initial access token of its own, the one
 * that grants the exchange: a token granting it gives it to every client it registers, and the provider
 * refuses the exchange to a client that does not register its grant.
 */
final readonly class TokenExchange implements FeatureClientInterface
{
    public const string HANDLE = 'token-exchange';
    private const string SERVICE = 'token-exchange-service';
    private const string ACCESS_TOKEN = 'urn:ietf:params:oauth:token-type:access_token';
    private const string SCOPE = 'invoices.read';

    public function __construct(
        private RegisteredClients $clients,
        private ProviderEndpoint $endpoint,
        private TheApiAccepts $api,
        private Runs $runs,
        private string $resource,
        private string $exchangeInitialAccessToken,
    ) {
    }

    public function title(): string
    {
        return 'Token exchange';
    }

    public function does(): string
    {
        return 'A gateway swaps the token of a service for one that acts on its behalf.';
    }

    public function view(): ClientView
    {
        return new ClientView(
            client: 'A gateway',
            clientId: $this->clients->clientIdOf(self::HANDLE),
            source: 'Its registration (RFC 7591); the exchange is granted by an initial access token of its own',
            lines: ConfigurationLines::json($this->clients->metadataOf(self::HANDLE) ?? $this->gateway(), ['grant_types', 'token_exchange']),
            run: $this->runs->of(self::HANDLE),
            notice: $this->exchangeInitialAccessToken === ''
                ? 'Set EXCHANGE_INITIAL_ACCESS_TOKEN in .env.local: bin/console beffroi:client:token:issue exchange --resource ' . $this->resource . ' --exchange-subject-token-type ' . self::ACCESS_TOKEN
                : null,
        );
    }

    public function status(): string
    {
        return RunStatus::of($this->runs->of(self::HANDLE));
    }

    public function runFields(): array
    {
        return [];
    }

    public function run(Request $request, string $back): Response
    {
        if ($this->exchangeInitialAccessToken === '') {
            $this->runs->failed(self::HANDLE, 'The gateway is registered with an initial access token that grants the exchange: EXCHANGE_INITIAL_ACCESS_TOKEN is empty.');

            return new RedirectResponse($back);
        }

        $proofs = [];
        try {
            $service = $this->clients->ensure(self::SERVICE, $this->service());
            $gateway = $this->clients->ensure(self::HANDLE, $this->gateway(), $this->exchangeInitialAccessToken);

            $subject = $this->clientCredentials($service, 'The service gets its token', $proofs);
            $actor = $this->clientCredentials($gateway, 'The gateway gets its own, the actor', $proofs);
            $exchanged = $this->endpoint->post('token_endpoint', [
                'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
                'subject_token' => $subject,
                'subject_token_type' => self::ACCESS_TOKEN,
                'actor_token' => $actor,
                'actor_token_type' => self::ACCESS_TOKEN,
                'resource' => $this->resource,
                'scope' => self::SCOPE,
            ], $gateway['client_id'], $gateway['client_secret']);
        } catch (ForgeException $exception) {
            $this->runs->failed(self::HANDLE, $exception->getMessage(), $proofs);

            return new RedirectResponse($back);
        }

        $proofs[] = IssuedToken::proof(sprintf('Exchanged → %d', $exchanged['status']), $exchanged['body']);
        $accessToken = $exchanged['body']['access_token'] ?? null;
        if ($exchanged['status'] !== 200 || ! is_string($accessToken)) {
            $this->runs->failed(self::HANDLE, OAuthError::of($exchanged['body']), $proofs);

            return new RedirectResponse($back);
        }
        $accepted = $this->api->proof($accessToken);
        $proofs[] = $accepted;
        $accepted['ok']
            ? $this->runs->worked(self::HANDLE, $proofs)
            : $this->runs->failed(self::HANDLE, $accepted['what'], $proofs);

        return new RedirectResponse($back);
    }

    /**
     * @param array{client_id: string, client_secret: string|null, answer: array<string, mixed>} $client
     * @param list<array{label: string, what: string, payload: string|null}> $proofs
     *
     * @throws ForgeException when the provider issues no token
     */
    private function clientCredentials(array $client, string $label, array &$proofs): string
    {
        $answer = $this->endpoint->post('token_endpoint', [
            'grant_type' => 'client_credentials',
            'scope' => self::SCOPE,
            'resource' => $this->resource,
        ], $client['client_id'], $client['client_secret']);
        $proofs[] = IssuedToken::proof(sprintf('%s → %d', $label, $answer['status']), $answer['body']);
        $token = $answer['body']['access_token'] ?? null;
        if ($answer['status'] !== 200 || ! is_string($token)) {
            throw new ForgeException(OAuthError::of($answer['body']));
        }

        return $token;
    }

    /**
     * @return array<string, mixed>
     */
    private function service(): array
    {
        return [
            'client_name' => 'Beffroi demo: the service behind a gateway',
            'grant_types' => ['client_credentials'],
            'token_endpoint_auth_method' => 'client_secret_basic',
            'scope' => self::SCOPE,
        ];
    }

    /**
     * @return array<string, mixed>
     */
    private function gateway(): array
    {
        return [
            'client_name' => 'Beffroi demo: a gateway',
            'grant_types' => ['client_credentials', 'urn:ietf:params:oauth:grant-type:token-exchange'],
            'token_endpoint_auth_method' => 'client_secret_basic',
            'scope' => self::SCOPE,
        ];
    }
}
