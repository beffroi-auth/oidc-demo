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
 * RFC 6749 §4.4: a service with nobody behind it asks a token for itself, for the API it names
 * (RFC 8707 §2), which the initial access token granted it.
 */
final readonly class ClientCredentials implements FeatureClientInterface
{
    public const string HANDLE = 'client-credentials';
    private const string SCOPE = 'invoices.read';

    public function __construct(
        private RegisteredClients $clients,
        private ProviderEndpoint $endpoint,
        private TheApiAccepts $api,
        private Runs $runs,
        private string $resource,
    ) {
    }

    public function title(): string
    {
        return 'Client credentials';
    }

    public function does(): string
    {
        return 'A service with no user gets a token for the API, and the API accepts it.';
    }

    public function view(): ClientView
    {
        return new ClientView(
            client: 'A service',
            clientId: $this->clients->clientIdOf(self::HANDLE),
            source: 'Its registration (RFC 7591); the token request adds resource=' . $this->resource,
            lines: ConfigurationLines::json($this->clients->metadataOf(self::HANDLE) ?? $this->registration(), ['grant_types', 'resources']),
            run: $this->runs->of(self::HANDLE),
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
        try {
            $client = $this->clients->ensure(self::HANDLE, $this->registration());
            $answer = $this->endpoint->post('token_endpoint', [
                'grant_type' => 'client_credentials',
                'scope' => self::SCOPE,
                'resource' => $this->resource,
            ], $client['client_id'], $client['client_secret']);
        } catch (ForgeException $exception) {
            $this->runs->failed(self::HANDLE, $exception->getMessage());

            return new RedirectResponse($back);
        }

        $proofs = [IssuedToken::proof(sprintf('Token endpoint → %d', $answer['status']), $answer['body'])];
        $accessToken = $answer['body']['access_token'] ?? null;
        if ($answer['status'] !== 200 || ! is_string($accessToken)) {
            $this->runs->failed(self::HANDLE, OAuthError::of($answer['body']), $proofs);

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
     * @return array<string, mixed>
     */
    private function registration(): array
    {
        return [
            'client_name' => 'Beffroi demo: a service',
            'grant_types' => ['client_credentials'],
            'token_endpoint_auth_method' => 'client_secret_basic',
            'scope' => self::SCOPE,
        ];
    }
}
