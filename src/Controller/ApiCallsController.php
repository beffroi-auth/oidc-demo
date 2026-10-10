<?php

namespace App\Controller;

use App\Api\Console\CallsOfThePage;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * The page where the access token of this session is used against the API of this application: the token
 * the "main" firewall obtained is handed to the browser, which calls /api/v1 with it as any client would
 * (assets/controllers/api_controller.js), and the page shows the request and the answer.
 *
 * Nothing of the API is reached from here: the page offers calls and the browser makes them, so what the
 * API answers is what it would answer anybody holding that token. A browser that runs nothing reads the
 * command line of each call instead, which is the same request.
 *
 * The token is of this session and of nobody else, and the page is behind the firewall that holds it
 * (access_control, ROLE_USER). Any other token the demonstration handed out works too, which is what the
 * field above the calls is for: the API asks the provider as each client whose secret this application
 * holds (src/Api/WhicheverClientKnowsTheToken.php).
 */
final class ApiCallsController extends AbstractController
{
    public function __construct(
        private readonly CallsOfThePage $calls,
        private readonly string $clientId,
    ) {
    }

    #[Route('/api-calls', name: 'app_api_calls', methods: ['GET'])]
    public function __invoke(Request $request, Security $security): Response
    {
        $token = $security->getToken();

        return $this->render('demo/api_calls.html.twig', [
            'calls' => $this->calls->all(),
            'access_token' => $token?->getAttribute('oidc_access_token'),
            'client_id' => $this->clientId,
            'origin' => $request->getSchemeAndHttpHost(),
        ]);
    }
}
