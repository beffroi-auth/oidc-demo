<?php

declare(strict_types=1);

namespace App\Forge\Flow;

use App\Forge\BuiltClient;
use App\Forge\ForgeException;
use App\Forge\Offer;

/**
 * Back-Channel Logout 1.0 §2.6: the token the provider posts to a client to say that a session it signed
 * in has ended, wherever it ended. It is a security event token (RFC 8417) and not an ID token, so what
 * tells it from one is checked: the member of "events" that makes it a logout, and the absence of a
 * "nonce", which an ID token replayed here would carry.
 *
 * Its signature is verified against the keys of the provider before any claim of it is read, and what it
 * says of itself is held to the client it was posted to: a token signed for somebody else ends nothing
 * here.
 */
final readonly class LogoutTokenReader
{
    private const string EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    public function __construct(
        private Jwt $jwt,
        private Offer $offer,
    ) {
    }

    /**
     * @return string the session of the provider that ended
     *
     * @throws ForgeException when the token is not a logout token of this client
     */
    public function sessionOf(BuiltClient $client, ?string $logoutToken): string
    {
        if (! is_string($logoutToken) || $logoutToken === '') {
            throw new ForgeException('This request carries no logout token (Back-Channel Logout 1.0 §2.5).');
        }

        $claims = $this->jwt->verify($logoutToken);
        if (($claims['iss'] ?? null) !== $this->offer->issuer()) {
            throw new ForgeException('The logout token does not name this provider (Back-Channel Logout 1.0 §2.6).');
        }
        $audiences = array_filter(is_array($claims['aud'] ?? null) ? $claims['aud'] : [$claims['aud'] ?? null], is_string(...));
        if (! in_array($client->clientId, $audiences, true)) {
            throw new ForgeException('The logout token is not for this client (Back-Channel Logout 1.0 §2.6).');
        }
        if (isset($claims['nonce'])) {
            throw new ForgeException('A logout token carries no "nonce": this is an ID token (Back-Channel Logout 1.0 §2.6).');
        }
        $iat = $claims['iat'] ?? null;
        if (! is_int($iat) || $iat > $this->jwt->now() + Jwt::LIFETIME) {
            throw new ForgeException('The logout token was not issued at a moment this client accepts (Back-Channel Logout 1.0 §2.6).');
        }
        $events = $claims['events'] ?? null;
        if (! is_array($events) || ! array_key_exists(self::EVENT, $events)) {
            throw new ForgeException('What was posted is no logout event (Back-Channel Logout 1.0 §2.6).');
        }
        $session = $claims['sid'] ?? null;
        if (! is_string($session) || $session === '') {
            throw new ForgeException('The logout token names no session, which this client registered to be told (Back-Channel Logout 1.0 §2.6).');
        }

        return $session;
    }
}
