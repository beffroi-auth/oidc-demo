<?php

declare(strict_types=1);

namespace App\Showcase;

/**
 * The square of the tree for a run: "idle" when it never ran, "ok" when it worked, "ko" when it failed.
 */
final class RunStatus
{
    /**
     * @param array{worked: bool, ...}|null $run
     */
    public static function of(?array $run): string
    {
        return match (true) {
            $run === null => 'idle',
            $run['worked'] => 'ok',
            default => 'ko',
        };
    }
}
