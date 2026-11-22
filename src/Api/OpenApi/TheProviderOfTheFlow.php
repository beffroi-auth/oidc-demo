<?php

declare(strict_types=1);

namespace App\Api\OpenApi;

use ApiPlatform\OpenApi\Factory\OpenApiFactoryInterface;
use ApiPlatform\OpenApi\Model\SecurityScheme;
use ApiPlatform\OpenApi\OpenApi;
use App\Forge\ForgeException;
use App\Forge\Offer;
use Symfony\Component\DependencyInjection\Attribute\AsDecorator;

/**
 * Where the "oauth" scheme of the document sends a client: the endpoints the discovery document of the
 * provider announces, never written beside it, the authorization request asking for a token addressed to
 * this API (RFC 8707 §2). Swagger UI appends its own parameters after the one the URL already carries.
 */
#[AsDecorator('api_platform.openapi.factory')]
final readonly class TheProviderOfTheFlow implements OpenApiFactoryInterface
{
    public function __construct(
        private OpenApiFactoryInterface $decorated,
        private Offer $offer,
        private string $resource,
    ) {
    }

    public function __invoke(array $context = []): OpenApi
    {
        $openApi = ($this->decorated)($context);
        $components = $openApi->getComponents();
        $schemes = $components->getSecuritySchemes();
        $scheme = $schemes['oauth'] ?? null;
        $flow = $scheme instanceof SecurityScheme ? $scheme->getFlows()?->getAuthorizationCode() : null;
        if ($flow === null || ! $scheme instanceof SecurityScheme) {
            return $openApi;
        }

        try {
            $authorize = $this->offer->endpoint('authorization_endpoint');
            $token = $this->offer->endpoint('token_endpoint');
        } catch (ForgeException) {
            // a provider that cannot be read leaves the document as configured, and the page says so
            return $openApi;
        }

        $flow = $flow
            ->withAuthorizationUrl($authorize . '?' . http_build_query(['resource' => $this->resource], '', '&', \PHP_QUERY_RFC3986))
            ->withTokenUrl($token);
        $schemes['oauth'] = $scheme
            ->withFlows($scheme->getFlows()->withAuthorizationCode($flow))
            ->withDescription('OAuth 2.0 at the provider: authorization code with PKCE, a token addressed to this API.');

        return $openApi->withComponents($components->withSecuritySchemes($schemes));
    }
}
