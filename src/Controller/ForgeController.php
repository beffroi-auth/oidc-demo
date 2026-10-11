<?php

declare(strict_types=1);

namespace App\Controller;

use App\Forge\BuiltClients;
use App\Forge\Forge;
use App\Forge\ForgeException;
use App\Forge\Presets;
use App\Forge\TheForm;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The forge of clients (beffroi#582): the page where a client is composed option by option, built at the
 * provider by dynamic registration, and then signed in with.
 *
 * It replaced the ladder of six rungs, whose clients were written in the configuration of the provider
 * and whose capabilities were the six sets somebody had chosen. What a visitor chooses here is every
 * member the provider announces, and the six rungs are presets of this page.
 */
final class ForgeController extends AbstractController
{
    public function __construct(
        private readonly TheForm $form,
        private readonly Presets $presets,
        private readonly Forge $forge,
        private readonly BuiltClients $clients,
        private readonly string $providerUri,
    ) {
    }

    /**
     * The form, the presets, and the clients this browser has already built. "preset" fills the form with
     * one of the presets and "from" with the composition of a client that exists, so that a client is
     * taken apart and built again rather than composed from nothing twice.
     */
    #[Route('/', name: 'app_home', methods: ['GET'])]
    public function forge(Request $request): Response
    {
        return $this->page($request->query->getString('preset'), $request->query->getString('from'));
    }

    /**
     * What the form submits. A preset is submitted the same way, under the handle of that preset, so that
     * building it again replaces the client it named rather than leaving one behind at the provider.
     */
    #[Route('/forge/build', name: 'app_forge_build', methods: ['POST'])]
    public function build(Request $request): Response
    {
        /** @var array<string, mixed> $input */
        $input = $request->request->all();
        $preset = $request->request->getString('preset');
        $form = $preset === '' ? $input : $this->presets->of($preset)->form;

        try {
            $client = $this->forge->build($form, $preset === '' ? null : $preset);
        } catch (ForgeException $exception) {
            return $this->page($preset, '', $form, $exception->getMessage())
                ->setStatusCode(Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        // the page of a built client is behind the firewall of the forge, so asking for it without a
        // session is what starts the flow of that client: building it and signing in with it is one click
        return $this->redirectToRoute('app_forge_profile', [
            'handle' => $client->handle,
        ]);
    }

    /**
     * RFC 7592 §2.3: the client deletes itself at the provider, and this browser forgets it.
     */
    #[Route('/forge/{handle}/delete', name: 'app_forge_delete', requirements: ['handle' => '[a-z0-9-]+'], methods: ['POST'])]
    public function delete(string $handle): Response
    {
        if ($this->clients->holds($handle)) {
            $this->forge->unmake($this->clients->of($handle));
        }

        return $this->redirectToRoute('app_home');
    }

    /**
     * @param array<string, mixed>|null $filled
     */
    private function page(string $preset, string $from, ?array $filled = null, ?string $error = null): Response
    {
        if ($filled === null && $preset !== '') {
            $filled = $this->presets->of($preset)->form;
        }
        if ($filled === null && $from !== '' && $this->clients->holds($from)) {
            $filled = $this->clients->of($from)->form;
        }

        return $this->render('forge/index.html.twig', [
            'choices' => $this->form->choices(),
            'presets' => $this->presets->all(),
            'filled' => $filled ?? [],
            'chosen_preset' => $preset,
            'built' => $this->clients->all(),
            'holds_a_token' => $this->forge->holdsAnInitialAccessToken(),
            'error' => $error,
            'provider_uri' => $this->providerUri,
        ]);
    }
}
