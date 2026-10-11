<?php

declare(strict_types=1);

namespace App\Forge\Flow\Delivery;

use App\Forge\BuiltClient;
use Symfony\Component\HttpFoundation\Request;

/**
 * OAuth 2.0 Multiple Response Type Encoding Practices §2.1: the answer in the query of the redirection,
 * which is where the browser history, the referer and every log on the way can read it. It is what a
 * client gets when it asks for nothing else.
 */
final readonly class InTheQuery implements AuthorizationResponseInterface
{
    public function names(): array
    {
        return ['query'];
    }

    public function describe(): string
    {
        return 'query: code, state and iss in the URL of the redirection (RFC 9207 for the issuer)';
    }

    public function isSigned(): bool
    {
        return false;
    }

    public function isPosted(): bool
    {
        return false;
    }

    public function read(Request $request, BuiltClient $client): array
    {
        $parameters = $request->query->all();

        return [
            'parameters' => $parameters,
            'carried' => sprintf('%d parameters in the query: %s', count($parameters), implode(', ', array_keys($parameters))),
            'payload' => null,
        ];
    }
}
