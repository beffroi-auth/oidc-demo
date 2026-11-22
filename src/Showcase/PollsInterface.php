<?php

declare(strict_types=1);

namespace App\Showcase;

/**
 * A client whose run waits on somebody else, the user approving at the provider: the panel asks it again
 * every few seconds until the run ends, one way or the other.
 */
interface PollsInterface
{
    /**
     * Asks the provider once more; true when the run ended, whatever its outcome.
     */
    public function poll(): bool;
}
