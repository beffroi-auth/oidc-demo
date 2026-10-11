<?php

declare(strict_types=1);

namespace App\Forge\Flow\Delivery;

use App\Forge\BuiltClient;
use Symfony\Component\HttpFoundation\Request;

/**
 * OAuth 2.0 Form Post Response Mode §2: the provider answers with a page that posts the parameters back,
 * so nothing of the answer is in the URL, in the history of the browser or in a log on the way. What it
 * costs is a cross-site POST, which is what the session cookie of this application is "SameSite=None"
 * for (config/packages/framework.yaml).
 */
final readonly class Posted implements AuthorizationResponseInterface
{
    public function names(): array
    {
        return ['form_post'];
    }

    public function describe(): string
    {
        return 'form_post: a self-submitting page posts the answer back, nothing of it in the URL (Form Post Response Mode §2)';
    }

    public function isSigned(): bool
    {
        return false;
    }

    public function isPosted(): bool
    {
        return true;
    }

    public function read(Request $request, BuiltClient $client): array
    {
        $parameters = $request->request->all();

        return [
            'parameters' => $parameters,
            'carried' => sprintf('%d fields posted back: %s', count($parameters), implode(', ', array_keys($parameters))),
            'payload' => null,
        ];
    }
}
