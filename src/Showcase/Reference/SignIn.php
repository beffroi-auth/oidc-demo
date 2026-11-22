<?php

declare(strict_types=1);

namespace App\Showcase\Reference;

use App\Showcase\ClientView;
use App\Showcase\ConfigurationLines;
use App\Showcase\FeatureClientInterface;
use App\Showcase\ReadJwt;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

/**
 * The reference client: the "main" firewall on Symfony's own oidc_login, configured and never coded. What
 * proves it works is what the authenticator kept on the session it opened.
 */
final readonly class SignIn implements FeatureClientInterface
{
    use TargetPathTrait;

    public function __construct(
        private SecurityConfiguration $configuration,
        private MainSession $session,
        private UrlGeneratorInterface $urls,
        private string $clientId,
    ) {
    }

    public function title(): string
    {
        return "Symfony's oidc_login";
    }

    public function does(): string
    {
        return 'A Symfony application signs in with configuration alone, no line of code.';
    }

    public function view(): ClientView
    {
        $oidcLogin = $this->configuration->firewall('main')['oidc_login'] ?? [];

        return new ClientView(
            client: 'Firewall "main"',
            clientId: $this->clientId,
            source: 'config/packages/security.yaml',
            lines: ConfigurationLines::yaml(
                ['security' => ['firewalls' => ['main' => ['oidc_login' => $oidcLogin]]]],
                ['provider_uri', 'client_id', 'client_authentication'],
            ),
            run: $this->proof(),
            page: $this->urls->generate('app_profile'),
        );
    }

    public function status(): string
    {
        return $this->session->token() === null ? 'idle' : 'ok';
    }

    public function runFields(): array
    {
        return [];
    }

    public function run(Request $request, string $back): Response
    {
        $this->saveTargetPath($request->getSession(), 'main', $back);

        return new RedirectResponse($this->urls->generate('_oidc_login_start_main'));
    }

    /**
     * @return array{worked: bool, at: int, why: string|null, proofs: list<array{label: string, what: string, payload: string|null}>}|null
     */
    private function proof(): ?array
    {
        $token = $this->session->token();
        if ($token === null) {
            return null;
        }
        $idToken = ReadJwt::of($token->getAttribute('oidc_id_token'));
        $accessToken = ReadJwt::of($token->hasAttribute('oauth2_access_token') ? $token->getAttribute('oauth2_access_token') : null);
        $claims = $idToken['claims'] ?? [];
        $header = $idToken['header'] ?? [];

        $proofs = [
            [
                'label' => 'Signed in',
                'what' => sprintf('sub %s', self::text($claims['sub'] ?? null)),
                'payload' => null,
            ],
            [
                'label' => 'ID token verified by oidc_login',
                'what' => sprintf(
                    '%s, kid %s, issued by %s for %s',
                    self::text($header['alg'] ?? null),
                    self::text($header['kid'] ?? null),
                    self::text($claims['iss'] ?? null),
                    self::text($claims['aud'] ?? null),
                ),
                'payload' => (string) json_encode($claims, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES),
            ],
        ];
        if ($accessToken !== null) {
            $proofs[] = [
                'label' => 'Access token held',
                'what' => sprintf(
                    'typ %s, scope %s',
                    self::text($accessToken['header']['typ'] ?? null),
                    self::text($accessToken['claims']['scope'] ?? null),
                ),
                'payload' => (string) json_encode($accessToken['claims'], \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES),
            ];
        }
        if ($token->hasAttribute('oauth2_refresh_token') && is_string($token->getAttribute('oauth2_refresh_token'))) {
            $proofs[] = [
                'label' => 'Refresh token held',
                'what' => 'the access token is renewed in place before it expires',
                'payload' => null,
            ];
        }

        return [
            'worked' => true,
            'at' => is_int($claims['auth_time'] ?? null) ? $claims['auth_time'] : (is_int($claims['iat'] ?? null) ? $claims['iat'] : 0),
            'why' => null,
            'proofs' => $proofs,
        ];
    }

    private static function text(mixed $value): string
    {
        return match (true) {
            is_string($value) => $value,
            is_int($value) => (string) $value,
            is_array($value) => implode(', ', array_filter($value, is_string(...))),
            default => '?',
        };
    }
}
