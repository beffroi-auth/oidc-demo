<?php

declare(strict_types=1);

namespace App\Api;

use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Http\AccessToken\AccessTokenHandlerInterface;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;

/**
 * How the API decides whether an access token gets in, two ways.
 *
 * A token addressed to this API (RFC 8707 §2, its "aud") is an "at+jwt" the API verifies itself against
 * the keys of the provider (RFC 9068 §4), asking nothing: that is what a client this API never heard of,
 * Swagger UI among them, holds once it asked for this resource. Any other token is described by the
 * provider (RFC 7662), which answers only the client the token was issued to, so the clients whose secret
 * this application holds are asked in turn (WhicheverClientKnowsTheToken).
 *
 * Which way a token goes is read from its own claims, unverified: the handler it goes to verifies all of
 * it, and a token that lies about its audience is refused by the one it chose.
 */
final readonly class AddressedHereOrDescribed implements AccessTokenHandlerInterface
{
    public const string CHECKED = '_api_token_checked';

    public function __construct(
        private AccessTokenHandlerInterface $addressedHere,
        private AccessTokenHandlerInterface $described,
        private string $resource,
        private RequestStack $requests,
    ) {
    }

    public function getUserBadgeFrom(string $accessToken): UserBadge
    {
        $addressedHere = $this->resource !== '' && $this->isAddressedHere($accessToken);
        $badge = $addressedHere
            ? $this->addressedHere->getUserBadgeFrom($accessToken)
            : $this->described->getUserBadgeFrom($accessToken);

        $this->requests->getCurrentRequest()?->attributes->set(self::CHECKED, [
            'how' => $addressedHere ? 'at+jwt verified offline (RFC 9068)' : 'introspected at the provider (RFC 7662)',
            'claims' => $badge->getAttributes() ?? [],
        ]);

        return $badge;
    }

    private function isAddressedHere(string $accessToken): bool
    {
        $parts = explode('.', $accessToken);
        if (count($parts) !== 3) {
            return false;
        }
        $claims = json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), true);
        $audience = is_array($claims) ? ($claims['aud'] ?? null) : null;

        return $audience === $this->resource || (is_array($audience) && in_array($this->resource, $audience, true));
    }
}
