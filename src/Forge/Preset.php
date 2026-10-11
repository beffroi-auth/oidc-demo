<?php

declare(strict_types=1);

namespace App\Forge;

/**
 * A composition somebody wrote down, so that what the ladder of rungs showed can still be reached in one
 * click: a slug, what it is called, the sentence that says what it is for, and the form it fills.
 *
 * A preset is nothing but a filled form: it is submitted the way a form filled by hand is, read by
 * Composition::read() like any other, and it can be taken apart on the page before it is built. Nothing
 * of the provider knows it exists.
 */
final readonly class Preset
{
    /**
     * @param array<string, mixed> $form what this preset puts in the form of the forge
     */
    public function __construct(
        public string $slug,
        public string $name,
        public string $what,
        public array $form,
    ) {
    }
}
