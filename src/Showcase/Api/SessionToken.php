<?php

declare(strict_types=1);

namespace App\Showcase\Api;

use App\Showcase\ClientView;
use App\Showcase\ConfigurationLines;
use App\Showcase\FeatureClientInterface;
use App\Showcase\Reference\SecurityConfiguration;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * The API of /api/v1 called with the token the session of the reference client holds: that token is the
 * client's, not addressed to the API, so the API asks the provider about it (RFC 7662).
 */
final readonly class SessionToken implements FeatureClientInterface
{
    public function __construct(
        private SecurityConfiguration $configuration,
        private ApiJournal $journal,
        private UrlGeneratorInterface $urls,
        private string $clientId,
    ) {
    }

    public function title(): string
    {
        return 'Session token, introspected';
    }

    public function does(): string
    {
        return 'A signed-in page calls the API with its own token; the API asks the provider about it.';
    }

    public function view(): ClientView
    {
        $described = $this->configuration->firewall('api_v1_described')['access_token'] ?? [];

        return new ClientView(
            client: 'Firewall "main", calling /api/v1',
            clientId: $this->clientId,
            source: 'How the API reads a token that is not addressed to it: config/packages/security.yaml',
            lines: ConfigurationLines::yaml(['access_token' => $described], ['http_client', 'audience']),
            run: CallsAsProof::of($this->calls()),
            page: $this->urls->generate('app_api_calls'),
            pageLabel: 'Open the page',
            hint: 'Run it, then call the API from the page: each call is ticked here.',
        );
    }

    public function status(): string
    {
        $run = CallsAsProof::of($this->calls());
        if ($run === null) {
            return 'idle';
        }

        return $run['worked'] ? 'ok' : 'ko';
    }

    public function runFields(): array
    {
        return [];
    }

    public function run(Request $request, string $back): Response
    {
        return new RedirectResponse($this->urls->generate('app_api_calls'));
    }

    /**
     * @return list<array{at: int, call: string, status: int, how: string|null, client_id: string|null, sub: string|null, scope: string|null, error: string|null}>
     */
    private function calls(): array
    {
        return array_values(array_filter(
            $this->journal->calls(),
            fn (array $call): bool => $call['client_id'] === $this->clientId,
        ));
    }
}
