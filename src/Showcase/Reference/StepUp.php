<?php

declare(strict_types=1);

namespace App\Showcase\Reference;

use App\Security\Acr\AcrReAuthenticationHandler;
use App\Showcase\ClientView;
use App\Showcase\ConfigurationLines;
use App\Showcase\FeatureClientInterface;
use App\Showcase\ReadJwt;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * The vault of the reference client: a route that requires an authentication context class rather than a
 * role, so that a session opened with a password is sent back to the provider for a passkey (OpenID
 * Connect EAP ACR Values 1.0). What proves it is the "acr" oidc_login kept from the new ID token.
 */
final readonly class StepUp implements FeatureClientInterface
{
    /**
     * @param list<string> $acceptedClasses
     */
    public function __construct(
        private SecurityConfiguration $configuration,
        private MainSession $session,
        private UrlGeneratorInterface $urls,
        private string $clientId,
        private array $acceptedClasses,
    ) {
    }

    public function title(): string
    {
        return 'Passkey step-up';
    }

    public function does(): string
    {
        return 'A page demands a passkey: the provider asks for one before letting the user in.';
    }

    public function view(): ClientView
    {
        return new ClientView(
            client: 'Firewall "main"',
            clientId: $this->clientId,
            source: 'config/packages/security.yaml and config/services.yaml',
            lines: ConfigurationLines::yaml(
                [
                    'security' => [
                        'firewalls' => ['main' => ['access_denied_handler' => AcrReAuthenticationHandler::class]],
                        'access_control' => $this->configuration->accessRulesOf('^/vault'),
                    ],
                    'parameters' => ['app.acr.accepted_classes' => $this->acceptedClasses],
                ],
                ['access_control', 'app.acr.accepted_classes'],
            ),
            run: $this->proof(),
            page: $this->urls->generate('app_vault'),
        );
    }

    public function status(): string
    {
        return $this->acr() === null ? 'idle' : 'ok';
    }

    public function runFields(): array
    {
        return [];
    }

    public function run(Request $request, string $back): Response
    {
        return new RedirectResponse($this->urls->generate('app_vault'));
    }

    private function acr(): ?string
    {
        $token = $this->session->token();
        $acr = $token?->hasAttribute('oidc_acr') === true ? $token->getAttribute('oidc_acr') : null;

        return is_string($acr) && in_array($acr, $this->acceptedClasses, true) ? $acr : null;
    }

    /**
     * @return array{worked: bool, at: int, why: string|null, proofs: list<array{label: string, what: string, payload: string|null}>}|null
     */
    private function proof(): ?array
    {
        $acr = $this->acr();
        $token = $this->session->token();
        if ($acr === null || $token === null) {
            return null;
        }
        $claims = ReadJwt::of($token->getAttribute('oidc_id_token'))['claims'] ?? [];
        $amr = is_array($claims['amr'] ?? null) ? implode(', ', array_filter($claims['amr'], is_string(...))) : '?';
        $authTime = is_int($claims['auth_time'] ?? null) ? $claims['auth_time'] : 0;

        return [
            'worked' => true,
            'at' => $authTime,
            'why' => null,
            'proofs' => [
                [
                    'label' => 'Sent back for a passkey',
                    'what' => sprintf('acr_values=%s, prompt=login', implode(' ', $this->acceptedClasses)),
                    'payload' => null,
                ],
                [
                    'label' => 'Signed in with a passkey',
                    'what' => sprintf('acr %s, amr %s', $acr, $amr),
                    'payload' => (string) json_encode($claims, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES),
                ],
                [
                    'label' => 'Let into the vault',
                    'what' => 'REQUIRES_PHR granted on the acr oidc_login kept',
                    'payload' => null,
                ],
            ],
        ];
    }
}
