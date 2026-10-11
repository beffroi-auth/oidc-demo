<?php

declare(strict_types=1);

namespace App\Forge;

/**
 * What the forge raises: a composition the provider does not offer, a registration it refused, a document
 * of a flow that does not hold. It carries what the page of the forge shows, so its message names the
 * member and the value rather than the step.
 */
final class ForgeException extends \RuntimeException
{
}
