<?php

declare(strict_types=1);

namespace App\Forge\Composed;

use App\Forge\Chosen;
use App\Forge\Offer;

/**
 * What a logout reaches: the logout page of the provider loading a URI of this client in a frame
 * (Front-Channel Logout 1.0 §3), the provider posting it a logout token wherever the session ended
 * (Back-Channel Logout 1.0 §2.5), or neither, in which case the client learns of a logout only when the
 * browser comes back to it.
 *
 * Where those two URIs are is the forge's, each built client having its own, so this says which ones it
 * registers and never what they are.
 */
final readonly class TheLogout
{
    public function __construct(
        public bool $frontChannel,
        public bool $backChannel,
        public bool $sessionRequired,
    ) {
    }

    /**
     * @param array<string, mixed> $input
     */
    public static function read(array $input, Offer $offer): self
    {
        return new self(
            Chosen::asked($input['frontchannel_logout'] ?? null) && $offer->says('frontchannel_logout_supported'),
            Chosen::asked($input['backchannel_logout'] ?? null) && $offer->says('backchannel_logout_supported'),
            Chosen::asked($input['logout_session_required'] ?? null),
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function registration(string $frontChannelUri, string $backChannelUri): array
    {
        $members = [];
        if ($this->frontChannel) {
            $members['frontchannel_logout_uri'] = $frontChannelUri;
            $members['frontchannel_logout_session_required'] = $this->sessionRequired;
        }
        if ($this->backChannel) {
            $members['backchannel_logout_uri'] = $backChannelUri;
            $members['backchannel_logout_session_required'] = $this->sessionRequired;
        }

        return $members;
    }
}
