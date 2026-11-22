<?php

declare(strict_types=1);

namespace App\Showcase\Grant;

/**
 * RFC 6749 §5.2: what an endpoint of the provider said when it refused, in its own words.
 */
final class OAuthError
{
    /**
     * @param array<string, mixed> $body
     */
    public static function of(array $body): string
    {
        $error = is_string($body['error'] ?? null) ? $body['error'] : 'no error code';
        $description = is_string($body['error_description'] ?? null) ? $body['error_description'] : null;

        return $description === null ? sprintf('The provider answered %s.', $error) : sprintf('The provider answered %s: %s', $error, $description);
    }
}
