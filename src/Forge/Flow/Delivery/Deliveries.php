<?php

declare(strict_types=1);

namespace App\Forge\Flow\Delivery;

use App\Forge\ForgeException;

/**
 * The shapes of answer the demonstration can read, each naming the response modes it answers to. The form
 * of the forge offers the modes the provider announces that are in here and no other, so a mode nothing
 * here reads is a gap and never a choice that would fail at the callback.
 */
final readonly class Deliveries
{
    /**
     * @param iterable<AuthorizationResponseInterface> $shapes
     */
    public function __construct(
        private iterable $shapes,
    ) {
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        $names = [];
        foreach ($this->shapes as $shape) {
            foreach ($shape->names() as $name) {
                $names[] = $name;
            }
        }

        return $names;
    }

    /**
     * @throws ForgeException when nothing here reads an answer of that mode
     */
    public function forMode(string $mode): AuthorizationResponseInterface
    {
        foreach ($this->shapes as $shape) {
            if (in_array($mode, $shape->names(), true)) {
                return $shape;
            }
        }

        throw new ForgeException(sprintf(
            'The demonstration cannot read an authorization response in "%s": it reads %s.',
            $mode,
            implode(', ', $this->names()),
        ));
    }
}
