<?php

declare(strict_types=1);

namespace App\Forge\Flow\Binding;

use App\Forge\ForgeException;

/**
 * The kinds of binding the demonstration can hold a token under, each naming itself. The form offers
 * those names, so a kind written here is a choice and a kind nobody wrote is not offered.
 */
final readonly class Bindings
{
    /**
     * @param iterable<TokenBindingInterface> $kinds
     */
    public function __construct(
        private iterable $kinds,
    ) {
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        $names = [];
        foreach ($this->kinds as $kind) {
            $names[] = $kind->name();
        }

        return $names;
    }

    /**
     * @throws ForgeException when nothing here holds a token that way
     */
    public function named(string $name): TokenBindingInterface
    {
        foreach ($this->kinds as $kind) {
            if ($kind->name() === $name) {
                return $kind;
            }
        }

        throw new ForgeException(sprintf(
            'The demonstration cannot hold a token bound to "%s": it holds %s.',
            $name,
            implode(', ', $this->names()),
        ));
    }
}
