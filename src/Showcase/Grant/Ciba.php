<?php

declare(strict_types=1);

namespace App\Showcase\Grant;

use App\Forge\ForgeException;
use App\Forge\Offer;
use App\Showcase\ClientView;
use App\Showcase\ConfigurationLines;
use App\Showcase\FeatureClientInterface;
use App\Showcase\PollsInterface;
use App\Showcase\ReadJwt;
use App\Showcase\Reference\MainSession;
use App\Showcase\RegisteredClients;
use App\Showcase\Runs;
use App\Showcase\RunStatus;
use App\Showcase\Waiting;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * CIBA Core 1.0: a client that is not where the user is, a call centre or a till, asks the provider to
 * authenticate a user it names, and polls while the user approves on their own device. It names the user
 * by the "sub" the provider issued (§7.1 "login_hint", read as a subject by default on this provider),
 * which this demonstration knows once the user signed in with its reference client.
 */
final readonly class Ciba implements FeatureClientInterface, PollsInterface
{
    public const string HANDLE = 'ciba';
    private const string GRANT = 'urn:openid:params:grant-type:ciba';

    public function __construct(
        private RegisteredClients $clients,
        private ProviderEndpoint $endpoint,
        private TokenPolling $polling,
        private Waiting $waiting,
        private Runs $runs,
        private MainSession $session,
        private Offer $offer,
    ) {
    }

    public function title(): string
    {
        return 'CIBA';
    }

    public function does(): string
    {
        return 'A call centre asks the provider to authenticate you; you approve elsewhere.';
    }

    public function view(): ClientView
    {
        $waiting = $this->waiting->of(self::HANDLE);

        return new ClientView(
            client: 'A call centre',
            clientId: $this->clients->clientIdOf(self::HANDLE),
            source: 'Its registration (RFC 7591)',
            lines: ConfigurationLines::json($this->clients->metadataOf(self::HANDLE) ?? $this->registration(), ['grant_types', 'backchannel_token_delivery_mode']),
            run: $this->runs->of(self::HANDLE),
            notice: $this->subject() === null ? "It names the user by the sub the provider issued: sign in with Symfony's oidc_login first." : null,
            waiting: $waiting === null ? null : [
                'says' => 'Approve the request on the provider. It shows the same binding message:',
                'code' => is_string($waiting['binding_message'] ?? null) ? $waiting['binding_message'] : null,
                'link' => $this->offer->issuer() . '/account/approvals',
                'linkLabel' => 'Approve it on the provider',
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
        $subject = $this->subject();
        if ($subject === null) {
            $this->runs->failed(self::HANDLE, "Sign in with Symfony's oidc_login first: this client names the user by the sub the provider issued.");

            return new RedirectResponse($back);
        }

        $bindingMessage = sprintf('DEMO-%04d', random_int(0, 9999));
        try {
            $client = $this->clients->ensure(self::HANDLE, $this->registration());
            $answer = $this->endpoint->post('backchannel_authentication_endpoint', [
                'scope' => 'openid profile',
                'login_hint' => $subject,
                'binding_message' => $bindingMessage,
            ], $client['client_id'], $client['client_secret']);
        } catch (ForgeException $exception) {
            $this->runs->failed(self::HANDLE, $exception->getMessage());

            return new RedirectResponse($back);
        }

        $body = $answer['body'];
        if ($answer['status'] !== 200 || ! is_string($body['auth_req_id'] ?? null)) {
            $this->runs->failed(self::HANDLE, OAuthError::of($body));

            return new RedirectResponse($back);
        }

        $this->polling->wait(
            self::HANDLE,
            is_int($body['interval'] ?? null) ? $body['interval'] : 5,
            is_int($body['expires_in'] ?? null) ? $body['expires_in'] : 300,
            [[
                'label' => 'Backchannel authentication request (CIBA Core §7)',
                'what' => sprintf('login_hint %s, binding_message %s, an auth_req_id back', $subject, $bindingMessage),
                'payload' => null,
            ]],
            ['auth_req_id' => $body['auth_req_id'], 'binding_message' => $bindingMessage],
        );

        return new RedirectResponse($back);
    }

    public function poll(): bool
    {
        $state = $this->waiting->of(self::HANDLE);
        $client = $this->clients->clientIdOf(self::HANDLE);
        if ($state === null || $client === null || ! is_string($state['auth_req_id'] ?? null)) {
            return true;
        }

        return $this->polling->poll(self::HANDLE, [
            'grant_type' => self::GRANT,
            'auth_req_id' => $state['auth_req_id'],
        ], $client, $this->clients->secretOf(self::HANDLE));
    }

    private function subject(): ?string
    {
        $token = $this->session->token();
        $sub = ReadJwt::of($token?->getAttribute('oidc_id_token'))['claims']['sub'] ?? null;

        return is_string($sub) && $sub !== '' ? $sub : null;
    }

    /**
     * @return array<string, mixed>
     */
    private function registration(): array
    {
        return [
            'client_name' => 'Beffroi demo: a call centre',
            'grant_types' => [self::GRANT, 'refresh_token'],
            'token_endpoint_auth_method' => 'client_secret_basic',
            'scope' => 'openid profile offline_access',
            'backchannel_token_delivery_mode' => 'poll',
        ];
    }
}
