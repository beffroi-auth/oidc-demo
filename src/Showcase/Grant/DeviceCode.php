<?php

declare(strict_types=1);

namespace App\Showcase\Grant;

use App\Forge\ForgeException;
use App\Showcase\ClientView;
use App\Showcase\ConfigurationLines;
use App\Showcase\FeatureClientInterface;
use App\Showcase\PollsInterface;
use App\Showcase\RegisteredClients;
use App\Showcase\Runs;
use App\Showcase\RunStatus;
use App\Showcase\Waiting;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * RFC 8628: a device with no browser and no keyboard worth typing on asks for a code, shows it, and waits
 * while the user allows it from any browser. It holds no secret: a device cannot keep one.
 */
final readonly class DeviceCode implements FeatureClientInterface, PollsInterface
{
    public const string HANDLE = 'device-code';
    private const string GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
    private const string SCOPE = 'openid profile offline_access';

    public function __construct(
        private RegisteredClients $clients,
        private ProviderEndpoint $endpoint,
        private TokenPolling $polling,
        private Waiting $waiting,
        private Runs $runs,
    ) {
    }

    public function title(): string
    {
        return 'Device code';
    }

    public function does(): string
    {
        return 'A TV with no browser shows a code; you allow it from your phone.';
    }

    public function view(): ClientView
    {
        $waiting = $this->waiting->of(self::HANDLE);

        return new ClientView(
            client: 'A device, a public client',
            clientId: $this->clients->clientIdOf(self::HANDLE),
            source: 'Its registration (RFC 7591)',
            lines: ConfigurationLines::json($this->clients->metadataOf(self::HANDLE) ?? $this->registration(), ['grant_types', 'token_endpoint_auth_method']),
            run: $this->runs->of(self::HANDLE),
            waiting: $waiting === null ? null : [
                'says' => 'Open the provider in any browser, sign in and allow this device. It shows the same code:',
                'code' => is_string($waiting['user_code'] ?? null) ? $waiting['user_code'] : null,
                'link' => is_string($waiting['link'] ?? null) ? $waiting['link'] : null,
                'linkLabel' => 'Allow it on the provider',
                'interval' => is_int($waiting['interval'] ?? null) ? $waiting['interval'] : 5,
            ],
        );
    }

    public function status(): string
    {
        return $this->waiting->of(self::HANDLE) !== null ? 'idle' : RunStatus::of($this->runs->of(self::HANDLE));
    }

    public function runFields(): array
    {
        return [];
    }

    public function run(Request $request, string $back): Response
    {
        try {
            $client = $this->clients->ensure(self::HANDLE, $this->registration());
            $answer = $this->endpoint->post('device_authorization_endpoint', ['scope' => self::SCOPE], $client['client_id'], null);
        } catch (ForgeException $exception) {
            $this->runs->failed(self::HANDLE, $exception->getMessage());

            return new RedirectResponse($back);
        }

        $body = $answer['body'];
        if ($answer['status'] !== 200 || ! is_string($body['device_code'] ?? null)) {
            $this->runs->failed(self::HANDLE, OAuthError::of($body));

            return new RedirectResponse($back);
        }

        $link = $body['verification_uri_complete'] ?? $body['verification_uri'] ?? null;
        $this->polling->wait(
            self::HANDLE,
            is_int($body['interval'] ?? null) ? $body['interval'] : 5,
            is_int($body['expires_in'] ?? null) ? $body['expires_in'] : 600,
            [[
                'label' => 'Device authorization (RFC 8628 §3.2)',
                'what' => sprintf('user_code %s, at %s', IssuedToken::text($body['user_code'] ?? null), IssuedToken::text($body['verification_uri'] ?? null)),
                'payload' => null,
            ]],
            ['device_code' => $body['device_code'], 'user_code' => $body['user_code'] ?? null, 'link' => $link, 'client_id' => $client['client_id']],
        );

        return new RedirectResponse($back);
    }

    public function poll(): bool
    {
        $state = $this->waiting->of(self::HANDLE);
        if ($state === null || ! is_string($state['device_code'] ?? null) || ! is_string($state['client_id'] ?? null)) {
            return true;
        }

        return $this->polling->poll(self::HANDLE, [
            'grant_type' => self::GRANT,
            'device_code' => $state['device_code'],
        ], $state['client_id'], null);
    }

    /**
     * @return array<string, mixed>
     */
    private function registration(): array
    {
        return [
            'client_name' => 'Beffroi demo: a device',
            'grant_types' => [self::GRANT, 'refresh_token'],
            'token_endpoint_auth_method' => 'none',
            'scope' => self::SCOPE,
        ];
    }
}
