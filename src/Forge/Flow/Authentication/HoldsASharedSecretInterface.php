<?php

declare(strict_types=1);

namespace App\Forge\Flow\Authentication;

/**
 * A method whose credential is a secret the provider issues at registration (RFC 7591 §3.2.1): the forge
 * keeps what it was answered and draws nothing.
 */
interface HoldsASharedSecretInterface extends ClientAuthenticationInterface
{
}
