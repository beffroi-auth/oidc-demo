<?php

declare(strict_types=1);

namespace App\Showcase\Grant;

use App\Showcase\ReadJwt;

/**
 * What the token endpoint answered, as one step of a proof: what was said about the token, and the claims
 * of the access token when it is one a reader can open (RFC 9068).
 */
final class IssuedToken
{
    /**
     * @param array<string, mixed> $answer
     *
     * @return array{label: string, what: string, payload: string|null, ok: bool}
     */
    public static function proof(string $label, array $answer): array
    {
        if (! is_string($answer['access_token'] ?? null)) {
            return ['label' => $label, 'what' => OAuthError::of($answer), 'payload' => null, 'ok' => false];
        }
        $accessToken = ReadJwt::of($answer['access_token']);
        $claims = $accessToken['claims'] ?? [];
        $said = array_filter([
            'token_type ' . self::text($answer['token_type'] ?? null),
            isset($answer['issued_token_type']) ? 'issued_token_type ' . self::text($answer['issued_token_type']) : null,
            isset($answer['scope']) ? 'scope ' . self::text($answer['scope']) : null,
            isset($claims['sub']) ? 'sub ' . self::text($claims['sub']) : null,
            isset($claims['aud']) ? 'aud ' . self::text($claims['aud']) : null,
            isset($claims['act']) ? 'act ' . (string) json_encode($claims['act'], \JSON_UNESCAPED_SLASHES) : null,
            isset($answer['expires_in']) ? 'expires_in ' . self::text($answer['expires_in']) : null,
        ]);

        return [
            'label' => $label,
            'what' => implode(', ', $said),
            'payload' => $accessToken === null ? null : (string) json_encode($claims, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES),
            'ok' => true,
        ];
    }

    public static function text(mixed $value): string
    {
        return match (true) {
            is_string($value) => $value,
            is_int($value) => (string) $value,
            is_array($value) => implode(' ', array_filter($value, is_string(...))),
            default => '?',
        };
    }
}
