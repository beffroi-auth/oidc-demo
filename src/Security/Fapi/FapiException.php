<?php

declare(strict_types=1);

namespace App\Security\Fapi;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * What the FAPI rung refuses, with the reason written out: this is a demonstration, and the page that
 * catches it is there to say what did not hold rather than to hide it.
 */
final class FapiException extends AuthenticationException
{
    public function getMessageKey(): string
    {
        return $this->getMessage();
    }
}
