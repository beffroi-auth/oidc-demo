<?php

declare(strict_types=1);

namespace App\Showcase;

use App\Showcase\Api\SessionToken;
use App\Showcase\Api\SwaggerUi;
use App\Showcase\Forged\ForgedClients;
use App\Showcase\Grant\Ciba;
use App\Showcase\Grant\ClientCredentials;
use App\Showcase\Grant\DeviceCode;
use App\Showcase\Grant\JwtBearer;
use App\Showcase\Grant\TokenExchange;
use App\Showcase\Reference\SignIn;
use App\Showcase\Reference\StepUp;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/**
 * The tree of the features of the provider, grouped, each one facing the client that shows it.
 */
final class Catalogue
{
    /**
     * @var list<Group>|null
     */
    private ?array $groups = null;

    public function __construct(
        private readonly ForgedClients $forged,
        private readonly SignIn $signIn,
        private readonly StepUp $stepUp,
        private readonly SwaggerUi $swaggerUi,
        private readonly SessionToken $sessionToken,
        private readonly ClientCredentials $clientCredentials,
        private readonly TokenExchange $tokenExchange,
        private readonly DeviceCode $deviceCode,
        private readonly Ciba $ciba,
        private readonly JwtBearer $jwtBearer,
    ) {
    }

    /**
     * @return list<Group>
     */
    public function groups(): array
    {
        return $this->groups ??= [
            new Group('Sign in', [
                new Feature('oidc-login', $this->signIn),
                $this->forged('basic'),
                $this->forged('form-post'),
                $this->forged('jarm'),
                $this->forged('par'),
                $this->forged('jar'),
                $this->forged('pairwise'),
                $this->forged('public'),
                new Feature('passkey', $this->stepUp),
            ]),
            new Group('Client authentication', [
                $this->forged('secret-jwt'),
                $this->forged('key'),
                $this->forged('tls'),
                $this->forged('self-signed'),
            ]),
            new Group('Tokens', [
                $this->forged('dpop'),
                $this->forged('mtls-bound'),
                $this->forged('refresh'),
                $this->forged('rar'),
            ]),
            new Group('Protect an API', [
                new Feature(SwaggerUi::SLUG, $this->swaggerUi),
                new Feature('api-calls', $this->sessionToken),
            ]),
            new Group('Documents', [
                $this->forged('encrypted-id-token'),
                $this->forged('userinfo-jwt'),
            ]),
            new Group('Sign out', [
                $this->forged('frontchannel'),
                $this->forged('backchannel'),
            ]),
            new Group('Without a browser', [
                new Feature(ClientCredentials::HANDLE, $this->clientCredentials),
                new Feature(TokenExchange::HANDLE, $this->tokenExchange),
                new Feature(DeviceCode::HANDLE, $this->deviceCode),
                new Feature(Ciba::HANDLE, $this->ciba),
                new Feature(JwtBearer::HANDLE, $this->jwtBearer),
            ]),
            new Group('FAPI 2.0', [
                $this->forged('fapi'),
                $this->forged('fapi-mtls'),
            ]),
        ];
    }

    /**
     * @throws NotFoundHttpException when no feature has that slug
     */
    public function of(string $slug): Feature
    {
        foreach ($this->groups() as $group) {
            foreach ($group->features as $feature) {
                if ($feature->slug === $slug) {
                    return $feature;
                }
            }
        }

        throw new NotFoundHttpException(sprintf('No feature is called "%s".', $slug));
    }

    public function groupOf(Feature $feature): Group
    {
        foreach ($this->groups() as $group) {
            if (in_array($feature, $group->features, true)) {
                return $group;
            }
        }

        throw new NotFoundHttpException(sprintf('The feature "%s" belongs to no group.', $feature->slug));
    }

    private function forged(string $preset): Feature
    {
        return new Feature($preset, $this->forged->of($preset));
    }
}
