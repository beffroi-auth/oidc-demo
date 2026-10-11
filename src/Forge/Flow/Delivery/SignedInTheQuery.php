<?php

declare(strict_types=1);

namespace App\Forge\Flow\Delivery;

use App\Forge\BuiltClient;
use Symfony\Component\HttpFoundation\Request;

/**
 * JARM §4.1 and §4.3: the answer is one parameter in the query, a JWT the provider signed, so the
 * browser carries no code of its own and nothing on the way can take one parameter out of the answer and
 * leave the rest.
 *
 * It answers to two names, "query.jwt" and the alias "jwt", which the provider resolves to the mode of
 * the response type and which for a code flow is this one (JARM §4.3).
 */
final readonly class SignedInTheQuery implements AuthorizationResponseInterface
{
    public function __construct(
        private SignedResponse $signed,
    ) {
    }

    public function names(): array
    {
        return ['query.jwt', 'jwt'];
    }

    public function describe(): string
    {
        return 'query.jwt: one signed "response" parameter in the URL, which the client verifies before reading it (JARM §4.1)';
    }

    public function isSigned(): bool
    {
        return true;
    }

    public function isPosted(): bool
    {
        return false;
    }

    public function read(Request $request, BuiltClient $client): array
    {
        $response = $request->query->get('response');

        return $this->signed->read(is_string($response) ? $response : null, $client);
    }
}
