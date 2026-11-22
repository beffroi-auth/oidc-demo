<?php

declare(strict_types=1);

namespace App\Showcase\Grant;

use App\Forge\Flow\Jwt;
use App\Forge\ForgeException;
use App\Forge\Offer;
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
 * RFC 7523 §2.1: a client presents an assertion another identity system signed about one of its users, and
 * gets a token for the user of the tenant that identity is linked to. The tenant decides whom it trusts:
 * the issuer, its key, the clients that may present its assertions and the scopes it may vouch for, so
 * the configuration this panel shows is the tenant's, the one its operator sets.
 */
final readonly class JwtBearer implements FeatureClientInterface
{
    public const string HANDLE = 'jwt-bearer';
    private const string GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
    private const string SCOPE = 'invoices.read';
    private const string IDENTITY_PROVIDER = 'beffroi-demo';

    public function __construct(
        private RegisteredClients $clients,
        private ProviderEndpoint $endpoint,
        private TheApiAccepts $api,
        private AssertionIssuer $issuer,
        private Jwt $jwt,
        private Offer $offer,
        private Runs $runs,
        private string $resource,
    ) {
    }

    public function title(): string
    {
        return 'JWT bearer';
    }

    public function does(): string
    {
        return 'Another identity system vouches for a user; the client trades that for a token.';
    }

    public function view(): ClientView
    {
        $clientId = $this->clients->clientIdOf(self::HANDLE);

        return new ClientView(
            client: 'A client of a trusted issuer',
            clientId: $clientId,
            source: 'What the tenant trusts: BEFFROI_TRUSTED_ISSUERS of the provider, set by its operator',
            lines: ConfigurationLines::json([
                $this->issuer->issuer() => [
                    'jwks' => ['keys' => [$this->issuer->key()->toPublic()->all()]],
                    'signing_algorithms' => ['ES256'],
                    'clients' => [$clientId ?? 'the client_id of its first run'],
                    'identity_provider' => self::IDENTITY_PROVIDER,
                    'trusted_scopes' => [self::SCOPE],
                ],
            ], []),
            run: $this->runs->of(self::HANDLE),
            notice: sprintf(
                'The provider trusts this issuer once its operator sets the configuration above and links a user: bin/console beffroi:user:link <username> %s %s',
                self::IDENTITY_PROVIDER,
                $this->issuer->subject(),
            ),
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
        $now = $this->jwt->now();
        $claims = [
            'iss' => $this->issuer->issuer(),
            'sub' => $this->issuer->subject(),
            'aud' => $this->offer->issuer(),
            'iat' => $now,
            'exp' => $now + 120,
            'jti' => bin2hex(random_bytes(16)),
        ];
        $proofs = [[
            'label' => 'The issuer signs an assertion (RFC 7523 §3)',
            'what' => sprintf('iss %s, sub %s, aud %s, ES256', $claims['iss'], $claims['sub'], $claims['aud']),
            'payload' => (string) json_encode($claims, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES),
        ]];

        try {
            $client = $this->clients->ensure(self::HANDLE, $this->registration());
            $key = $this->issuer->key();
            $assertion = $this->jwt->sign($claims, $key, 'ES256', ['typ' => 'JWT']);
            $answer = $this->endpoint->post('token_endpoint', [
                'grant_type' => self::GRANT,
                'assertion' => $assertion,
                'scope' => self::SCOPE,
                'resource' => $this->resource,
            ], $client['client_id'], $client['client_secret']);
        } catch (ForgeException $exception) {
            $this->runs->failed(self::HANDLE, $exception->getMessage(), $proofs);

            return new RedirectResponse($back);
        }

        $proofs[] = IssuedToken::proof(sprintf('Token endpoint → %d', $answer['status']), $answer['body']);
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
            'client_name' => 'Beffroi demo: a client of a trusted issuer',
            'grant_types' => [self::GRANT],
            'token_endpoint_auth_method' => 'client_secret_basic',
            'scope' => self::SCOPE,
        ];
    }
}
