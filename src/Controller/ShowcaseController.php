<?php

declare(strict_types=1);

namespace App\Controller;

use App\Showcase\Catalogue;
use App\Showcase\PollsInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The tree of the features of the provider: each one faces a client, shows its configuration, and runs
 * it to show that it works.
 */
final class ShowcaseController extends AbstractController
{
    public function __construct(
        private readonly Catalogue $catalogue,
    ) {
    }

    /**
     * A client the forge deleted comes back here with what the provider answered (RFC 7592 §2.3), and
     * the page says it.
     */
    #[Route('/', name: 'app_home', methods: ['GET'])]
    public function home(Request $request): Response
    {
        return $this->render('showcase/home.html.twig', [
            'deleted' => $request->query->getString('deleted'),
            'answered' => $request->query->getString('answered'),
        ]);
    }

    #[Route('/f/{slug}', name: 'app_feature', requirements: ['slug' => '[a-z0-9-]+'], methods: ['GET'])]
    public function feature(string $slug): Response
    {
        $feature = $this->catalogue->of($slug);

        return $this->render('showcase/feature.html.twig', [
            'feature' => $feature,
            'group' => $this->catalogue->groupOf($feature),
            'view' => $feature->client->view(),
        ]);
    }

    #[Route('/f/{slug}/run', name: 'app_feature_run', requirements: ['slug' => '[a-z0-9-]+'], methods: ['POST'])]
    public function run(string $slug, Request $request): Response
    {
        return $this->catalogue->of($slug)->client->run(
            $request,
            $this->generateUrl('app_feature', ['slug' => $slug]),
        );
    }

    /**
     * A run that waits on the user is asked again here, by the page that shows it, until it ends.
     */
    #[Route('/f/{slug}/poll', name: 'app_feature_poll', requirements: ['slug' => '[a-z0-9-]+'], methods: ['POST'])]
    public function poll(string $slug): JsonResponse
    {
        $client = $this->catalogue->of($slug)->client;
        if (! $client instanceof PollsInterface) {
            throw new NotFoundHttpException(sprintf('The client of "%s" waits on nobody.', $slug));
        }

        return new JsonResponse(['ended' => $client->poll()]);
    }
}
