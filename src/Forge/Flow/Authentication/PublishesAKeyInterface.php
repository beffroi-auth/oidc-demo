<?php

declare(strict_types=1);

namespace App\Forge\Flow\Authentication;

/**
 * A method whose credential is a key the client publishes in its registration (RFC 7523 §2.2): the forge
 * draws the pair and registers the public half, the provider issuing no secret at all.
 */
interface PublishesAKeyInterface extends ClientAuthenticationInterface
{
}
