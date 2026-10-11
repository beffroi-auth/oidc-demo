<?php

declare(strict_types=1);

namespace App\Forge\Flow\Authentication;

use App\Forge\ForgeException;

/**
 * The methods the demonstration is wired with, each naming itself. The form of the forge offers the
 * methods the provider announces that are in here, and no other: a method the provider serves that
 * nothing here can play is not a choice, it is a gap, and a method written here that the provider stopped
 * announcing disappears from the form on its own.
 */
final readonly class ClientAuthentications
{
    /**
     * @param iterable<ClientAuthenticationInterface> $methods
     */
    public function __construct(
        private iterable $methods,
    ) {
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        $names = [];
        foreach ($this->methods as $method) {
            $names[] = $method->name();
        }

        return $names;
    }

    /**
     * @throws ForgeException when nothing here authenticates a client that way
     */
    public function named(string $name): ClientAuthenticationInterface
    {
        foreach ($this->methods as $method) {
            if ($method->name() === $name) {
                return $method;
            }
        }

        throw new ForgeException(sprintf(
            'The demonstration cannot authenticate a client with "%s": it is wired with %s.',
            $name,
            implode(', ', $this->names()),
        ));
    }
}
