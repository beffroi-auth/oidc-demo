<?php

declare(strict_types=1);

namespace App\Controller;

use App\Forge\BuiltClients;
use App\Forge\EndedSessions;
use App\Forge\Flow\FlowClient;
use App\Forge\Flow\LogoutTokenReader;
use App\Forge\Forge;
use App\Forge\ForgeException;
use App\Forge\WhatOidcLoginCannotServe;
use App\Security\Forge\ForgeAuthenticator;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\User\OidcUser;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

/**
 * The pages of a client the forge built (beffroi#582), one set of routes for every one of them: the page
 * it signs a user in to, the page that says why a login was refused, and the two URIs a logout reaches.
 *
 * Every route carries the handle of its client, which is how one firewall serves clients that do not
 * exist when the application boots.
 */
final class BuiltClientController extends AbstractController
{
    public function __construct(
        private readonly BuiltClients $clients,
        private readonly FlowClient $flow,
        private readonly Forge $forge,
        private readonly WhatOidcLoginCannotServe $gaps,
        private readonly string $providerUri,
    ) {
    }

    /**
     * Behind the firewall of the forge: asking for it without a session starts the flow of this client,
     * which is the whole demonstration. What it shows is what this client registered, what travelled in
     * each direction, what it holds, and what Symfony's own authenticator could not have served.
     */
    #[Route('/c/{handle}/profile', name: 'app_forge_profile', requirements: ['handle' => '[a-z0-9-]+'], methods: ['GET'])]
    public function profile(string $handle, Request $request, Security $security): Response
    {
        $client = $this->clients->of($handle);
        $composition = $this->flow->compositionOf($client);
        $token = $security->getToken();
        $user = $token?->getUser();
        $signedIn = $token?->hasAttribute(ForgeAuthenticator::HANDLE_ATTRIBUTE) === true
            && $token->getAttribute(ForgeAuthenticator::HANDLE_ATTRIBUTE) === $handle;

        return $this->render('forge/client.html.twig', [
            'client' => $client,
            // RFC 7592 §2.1: what the provider says of this client now, asked for at the URI it handed out
            // with the credential it handed out, and only when the page was asked to
            'read' => $request->query->getBoolean('read') ? $this->read($client) : null,
            'composition' => $composition,
            'described' => $this->flow->describe($composition),
            'gaps' => $this->gaps->of($composition),
            'user' => $signedIn ? $user : null,
            'claims' => $signedIn && $user instanceof OidcUser ? $user->getAdditionalClaims() : [],
            'tokens' => $signedIn && $token->hasAttribute(ForgeAuthenticator::TOKENS_ATTRIBUTE) ? $token->getAttribute(ForgeAuthenticator::TOKENS_ATTRIBUTE) : [],
            'hops' => $signedIn && $token->hasAttribute(ForgeAuthenticator::HOPS_ATTRIBUTE) ? $token->getAttribute(ForgeAuthenticator::HOPS_ATTRIBUTE) : [],
            'provider_uri' => $this->providerUri,
        ]);
    }

    /**
     * RFC 7592 §2.1: the registration as the provider holds it now, or what it answered instead. It is the
     * one way a dynamic client reads itself, and the page prints the answer whichever it is.
     *
     * @return array{answer: array<string, mixed>|null, said: string}
     */
    private function read(\App\Forge\BuiltClient $client): array
    {
        try {
            return [
                'answer' => $this->forge->read($client),
                'said' => 'the provider answered the registration it holds',
            ];
        } catch (ForgeException $exception) {
            return [
                'answer' => null,
                'said' => $exception->getMessage(),
            ];
        }
    }

    /**
     * Where a sign-in with this client starts on purpose: the page above starts it by being asked for
     * without a session, which is of no use to a browser that holds the session of another built client.
     * The entry point of the firewall answers here, so one route and one authenticator start every flow.
     */
    #[Route('/c/{handle}/start', name: 'app_forge_start', requirements: ['handle' => '[a-z0-9-]+'], methods: ['GET'])]
    public function start(Request $request, ForgeAuthenticator $authenticator): Response
    {
        return $authenticator->start($request);
    }

    /**
     * Where a refused login lands, so that the reason is read instead of being bounced back to the
     * provider for another try. A composition the provider refuses says so here, in its own words.
     */
    #[Route('/c/{handle}/login', name: 'app_forge_login', requirements: ['handle' => '[a-z0-9-]+'], methods: ['GET'])]
    public function login(string $handle, AuthenticationUtils $authenticationUtils): Response
    {
        return $this->render('forge/login.html.twig', [
            'handle' => $handle,
            'client' => $this->clients->holds($handle) ? $this->clients->of($handle) : null,
            'error' => $authenticationUtils->getLastAuthenticationError(),
            'provider_uri' => $this->providerUri,
        ]);
    }

    /**
     * Nothing runs here: the authenticator of this firewall answers the request before any controller
     * does, and the route exists so that the path has a name and both methods are declared, a posted
     * response arriving on a POST and every other on a GET.
     */
    #[Route('/c/{handle}/callback', name: 'app_forge_callback', requirements: ['handle' => '[a-z0-9-]+'], methods: ['GET', 'POST'])]
    public function callback(): Response
    {
        throw new \LogicException('The authenticator of the forge answers this path.');
    }

    /**
     * Front-Channel Logout 1.0 §3: the logout page of the provider loads this URI in a frame, in the
     * browser of the user and with its cookies, naming the session that ended. It ends the session of the
     * forge and nothing else: the reference client of the "main" firewall keeps its own.
     */
    #[Route('/c/{handle}/frontchannel-logout', name: 'app_forge_frontchannel_logout', requirements: ['handle' => '[a-z0-9-]+'], methods: ['GET'])]
    public function frontChannelLogout(string $handle, Request $request): Response
    {
        $session = $request->getSession();
        $key = '_security_' . ForgeAuthenticator::FIREWALL;
        $ended = false;

        // the provider says which session ended; a request naming another issuer is not one of its
        // logouts, and one naming no session is not one this client registered for
        if ($request->query->get('iss') === $this->providerUri && $request->query->get('sid') !== null && $session->has($key)) {
            $session->remove($key);
            $ended = true;
        }

        return $this->render('forge/frontchannel.html.twig', [
            'handle' => $handle,
            'ended' => $ended,
            'sid' => $request->query->get('sid'),
        ]);
    }

    /**
     * Back-Channel Logout 1.0 §2.5: the provider posts a logout token here, server to server, when a
     * session this client signed in has ended wherever it ended. The session it names is refused on the
     * next request the browser makes (EndedSessionListener), without the user going through any of it.
     *
     * §2.8: the answer is 200 with no body when the logout was taken, and 400 when the token was not one
     * this client accepts, which is what tells the provider to stop retrying.
     */
    #[Route('/c/{handle}/backchannel-logout', name: 'app_forge_backchannel_logout', requirements: ['handle' => '[a-z0-9-]+'], methods: ['POST'])]
    public function backChannelLogout(string $handle, Request $request, LogoutTokenReader $tokens, EndedSessions $ended): Response
    {
        try {
            $session = $tokens->sessionOf($this->clients->of($handle), $request->request->getString('logout_token'));
        } catch (ForgeException $exception) {
            return new Response((string) json_encode([
                'error' => 'invalid_request',
                'error_description' => $exception->getMessage(),
            ]), Response::HTTP_BAD_REQUEST, ['Content-Type' => 'application/json']);
        }

        $ended->end($session);

        return new Response('', Response::HTTP_OK, ['Cache-Control' => 'no-store']);
    }
}
