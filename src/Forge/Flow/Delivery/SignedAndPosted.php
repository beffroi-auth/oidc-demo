<?php

declare(strict_types=1);

namespace App\Forge\Flow\Delivery;

use App\Forge\BuiltClient;
use Symfony\Component\HttpFoundation\Request;

/**
 * JARM §4.1 with the posted mode: the same signed parameter, in the body of a POST the page of the
 * provider submits, so that it is neither in the URL nor readable by anything on the way.
 */
final readonly class SignedAndPosted implements AuthorizationResponseInterface
{
    public function __construct(
        private SignedResponse $signed,
    ) {
    }

    public function names(): array
    {
        return ['form_post.jwt'];
    }

    public function describe(): string
    {
        return 'form_post.jwt: one signed "response" field, posted back by a page of the provider (JARM §4.1)';
    }

    public function isSigned(): bool
    {
        return true;
    }

    public function isPosted(): bool
    {
        return true;
    }

    public function read(Request $request, BuiltClient $client): array
    {
        $response = $request->request->get('response');

        return $this->signed->read(is_string($response) ? $response : null, $client);
    }
}
