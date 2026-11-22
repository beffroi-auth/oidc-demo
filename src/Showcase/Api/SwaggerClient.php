<?php

declare(strict_types=1);

namespace App\Showcase\Api;

use App\Forge\ForgeException;
use App\Showcase\RegisteredClients;
use Symfony\Component\HttpFoundation\UrlHelper;

/**
 * Swagger UI as a client of the provider: a public client (RFC 6749 §2.1) that proves its code with PKCE,
 * registered by this demonstration (RFC 7591) for the page of the API, asking for tokens addressed to the
 * API (RFC 8707 §2). Its identifier is known once it is registered, so the page reads it from here.
 */
final readonly class SwaggerClient
{
    public const string HANDLE = 'swagger';

    /**
     * The page Swagger UI comes back to, as assets:install copies it into public/: the copy AssetMapper
     * serves under a versioned name loads its script by a relative path that name breaks.
     */
    public const string REDIRECT = '/bundles/apiplatform/swagger-ui/oauth2-redirect.html';

    public function __construct(
        private RegisteredClients $clients,
        private UrlHelper $urls,
    ) {
    }

    /**
     * RFC 7591 §2: what is sent to the registration endpoint.
     *
     * @return array<string, mixed>
     */
    public function registration(): array
    {
        return [
            'client_name' => 'Swagger UI of the demonstration',
            'token_endpoint_auth_method' => 'none',
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
            'redirect_uris' => [$this->urls->getAbsoluteUrl(self::REDIRECT)],
            'scope' => 'profile invoices.read invoices.pay invoices.write',
        ];
    }

    /**
     * RFC 7591 §3.2.1: the client as the provider registered it, the resources it may ask a token for
     * among them; a client never registers those itself, the initial access token grants them.
     *
     * @return array<string, mixed>|null
     */
    public function registered(): ?array
    {
        return $this->clients->metadataOf(self::HANDLE);
    }

    public function clientId(): ?string
    {
        return $this->clients->clientIdOf(self::HANDLE);
    }

    /**
     * @throws ForgeException when the provider refuses it
     */
    public function register(): string
    {
        return $this->clients->ensure(self::HANDLE, $this->registration())['client_id'];
    }
}
