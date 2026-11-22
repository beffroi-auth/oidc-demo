<?php

declare(strict_types=1);

namespace App\Showcase\Api;

use App\Forge\ForgeException;
use App\Showcase\ClientView;
use App\Showcase\ConfigurationLines;
use App\Showcase\FeatureClientInterface;
use App\Showcase\Runs;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * The API of /api/v1 seen from Swagger UI, the page API Platform serves for it: a public client the
 * demonstration registers, which signs the user in with PKCE and calls the API with a token addressed to
 * it. What proves it works is what the API answered its calls.
 */
final readonly class SwaggerUi implements FeatureClientInterface
{
    public const string SLUG = 'swagger';

    public function __construct(
        private SwaggerClient $client,
        private ApiJournal $journal,
        private Runs $runs,
        private UrlGeneratorInterface $urls,
    ) {
    }

    public function title(): string
    {
        return 'API with Swagger UI';
    }

    public function does(): string
    {
        return 'Swagger UI signs in with PKCE and calls the API with a token addressed to it.';
    }

    public function view(): ClientView
    {
        $failed = $this->runs->of(self::SLUG);

        return new ClientView(
            client: 'Swagger UI, a public client',
            clientId: $this->client->clientId(),
            source: $this->client->registered() === null
                ? 'Registered for /api/v1/docs on first run (RFC 7591); the initial access token grants it the API as a resource'
                : 'As the provider registered it (RFC 7591 §3.2.1), the API granted by the initial access token; the API verifies its tokens itself (RFC 9068)',
            lines: ConfigurationLines::json($this->client->registered() ?? $this->client->registration(), ['token_endpoint_auth_method', 'resources']),
            run: $failed !== null && ! $failed['worked'] ? $failed : CallsAsProof::of($this->calls()),
            page: $this->urls->generate('api_doc'),
            pageLabel: 'Open Swagger UI',
            hint: 'Run it, then Authorize in Swagger UI and call any operation: each call is ticked here.',
        );
    }

    public function status(): string
    {
        $run = $this->view()->run;
        if ($run === null) {
            return 'idle';
        }

        return $run['worked'] ? 'ok' : 'ko';
    }

    public function runFields(): array
    {
        return [];
    }

    /**
     * Registers Swagger UI when it is not yet, then opens it: what proves the feature is what the visitor
     * does there, "Authorize" and then any operation.
     */
    public function run(Request $request, string $back): Response
    {
        try {
            $this->client->register();
        } catch (ForgeException $exception) {
            $this->runs->failed(self::SLUG, $exception->getMessage());

            return new RedirectResponse($back);
        }
        $this->runs->forget(self::SLUG);

        return new RedirectResponse($this->urls->generate('api_doc'));
    }

    /**
     * @return list<array{at: int, call: string, status: int, how: string|null, client_id: string|null, sub: string|null, scope: string|null, error: string|null}>
     */
    private function calls(): array
    {
        $clientId = $this->client->clientId();

        return $clientId === null ? [] : array_values(array_filter(
            $this->journal->calls(),
            static fn (array $call): bool => $call['client_id'] === $clientId,
        ));
    }
}
