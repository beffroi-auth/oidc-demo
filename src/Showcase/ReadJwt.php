<?php

declare(strict_types=1);

namespace App\Showcase;

/**
 * The header and claims of a JWT, read for display: whatever is shown this way was verified by whoever
 * received it, or is shown as what travelled.
 */
final class ReadJwt
{
    /**
     * @return array{header: array<string, mixed>, claims: array<string, mixed>}|null
     */
    public static function of(mixed $jwt): ?array
    {
        if (! is_string($jwt)) {
            return null;
        }
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return null;
        }
        $header = json_decode((string) base64_decode(strtr($parts[0], '-_', '+/'), true), true);
        $claims = json_decode((string) base64_decode(strtr($parts[1], '-_', '+/'), true), true);
        if (! is_array($header) || ! is_array($claims)) {
            return null;
        }

        /** @var array{header: array<string, mixed>, claims: array<string, mixed>} */
        return ['header' => $header, 'claims' => $claims];
    }
}
