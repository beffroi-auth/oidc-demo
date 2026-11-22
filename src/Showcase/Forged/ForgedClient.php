<?php

declare(strict_types=1);

namespace App\Showcase\Forged;

use App\Forge\BuiltClients;
use App\Forge\Composition;
use App\Forge\Forge;
use App\Forge\ForgeException;
use App\Forge\Offer;
use App\Forge\Preset;
use App\Security\Forge\ForgeAuthenticator;
use App\Showcase\ClientView;
use App\Showcase\ConfigurationLines;
use App\Showcase\FeatureClientInterface;
use App\Showcase\Runs;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

/**
 * A client the forge builds from a preset, under the slug of that preset: its configuration is the
 * preset, the members that differ from the first preset being what makes the feature, and it is
 * registered at the provider the first time it runs (RFC 7591).
 */
final readonly class ForgedClient implements FeatureClientInterface
{
    use TargetPathTrait;

    public function __construct(
        private Preset $preset,
        private Preset $baseline,
        private Forge $forge,
        private BuiltClients $clients,
        private Offer $offer,
        private Runs $runs,
        private UrlGeneratorInterface $urls,
    ) {
    }

    public function title(): string
    {
        return $this->preset->name;
    }

    public function does(): string
    {
        return $this->preset->what;
    }

    public function view(): ClientView
    {
        $refusal = $this->refusal();
        $built = $this->clients->holds($this->preset->slug) ? $this->clients->of($this->preset->slug) : null;

        return new ClientView(
            client: $built?->name() ?? $this->preset->form['client_name'] ?? $this->preset->slug,
            clientId: $built?->clientId,
            source: 'Registered at the provider the first time it runs (RFC 7591)',
            lines: ConfigurationLines::json($this->preset->form, $this->highlighted()),
            run: $this->runs->of($this->preset->slug),
            offered: $refusal === null,
            notice: $refusal ?? ($built === null && ! $this->forge->holdsAnInitialAccessToken()
                ? 'The provider registers a client only with an initial access token: set FORGE_INITIAL_ACCESS_TOKEN in .env.local.'
                : null),
            page: $built === null ? null : $this->urls->generate('app_forge_profile', ['handle' => $built->handle]),
        );
    }

    public function status(): string
    {
        if ($this->refusal() !== null) {
            return 'off';
        }
        $run = $this->runs->of($this->preset->slug);
        if ($run === null) {
            return 'idle';
        }

        return $run['worked'] ? 'ok' : 'ko';
    }

    public function runFields(): array
    {
        return ['preset' => $this->preset->slug];
    }

    public function run(Request $request, string $back): Response
    {
        $handle = $this->preset->slug;
        try {
            // a client built from another version of its preset is built again, so that what runs is what
            // the page shows
            if (! $this->clients->holds($handle) || $this->clients->of($handle)->form !== $this->preset->form) {
                $this->forge->build($this->preset->form, $handle);
            }
        } catch (ForgeException $exception) {
            $this->runs->failed($handle, $exception->getMessage());

            return new RedirectResponse($back);
        }

        $this->saveTargetPath($request->getSession(), ForgeAuthenticator::FIREWALL, $back);

        return new RedirectResponse($this->urls->generate('app_forge_start', ['handle' => $handle]));
    }

    /**
     * What the provider says against this composition, or null when it offers all of it.
     */
    private function refusal(): ?string
    {
        try {
            Composition::read($this->preset->form, $this->offer);

            return null;
        } catch (ForgeException $exception) {
            return $exception->getMessage();
        }
    }

    /**
     * @return list<string>
     */
    private function highlighted(): array
    {
        if ($this->preset->slug === $this->baseline->slug) {
            return [];
        }

        $differ = [];
        foreach ($this->preset->form as $key => $value) {
            if ($key !== 'client_name' && ($this->baseline->form[$key] ?? null) !== $value) {
                $differ[] = $key;
            }
        }

        return $differ;
    }
}
