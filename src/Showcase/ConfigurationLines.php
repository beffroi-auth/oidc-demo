<?php

declare(strict_types=1);

namespace App\Showcase;

use Symfony\Component\Yaml\Yaml;

/**
 * A configuration written out one line at a time, the lines of the members that make a feature marked so
 * that the eye goes to them first.
 */
final class ConfigurationLines
{
    /**
     * A JSON object, a list of strings kept on one line and a member holding a JSON document written as
     * that document.
     *
     * @param array<string, mixed> $values
     * @param list<string> $highlighted
     *
     * @return list<array{text: string, hl: bool}>
     */
    public static function json(array $values, array $highlighted): array
    {
        $lines = [['text' => '{', 'hl' => false]];
        $last = array_key_last($values);
        foreach ($values as $key => $value) {
            if (is_string($value) && is_array($decoded = json_decode($value, true))) {
                $value = $decoded;
            }
            $encoded = self::listsOnOneLine((string) json_encode($value, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES));
            $parts = explode("\n", sprintf('"%s": %s%s', $key, $encoded, $key === $last ? '' : ','));
            $hl = in_array($key, $highlighted, true);
            foreach ($parts as $part) {
                $lines[] = ['text' => '    ' . $part, 'hl' => $hl];
            }
        }
        $lines[] = ['text' => '}', 'hl' => false];

        return $lines;
    }

    /**
     * A list of plain values reads best on one line, at whatever depth it sits.
     */
    private static function listsOnOneLine(string $json): string
    {
        return (string) preg_replace_callback(
            '/\[\n(?:\s*(?:"[^"\n]*"|-?\d[\d.]*|true|false|null),?\n)+\s*\]/',
            static fn (array $list): string => (string) json_encode(json_decode($list[0], true), \JSON_UNESCAPED_SLASHES),
            $json,
        );
    }

    /**
     * YAML as Symfony reads it, a highlighted key taking the lines nested under it.
     *
     * @param array<string, mixed> $values
     * @param list<string> $highlighted
     *
     * @return list<array{text: string, hl: bool}>
     */
    public static function yaml(array $values, array $highlighted): array
    {
        $lines = [];
        $under = null;
        foreach (explode("\n", rtrim(Yaml::dump($values, 8, 4))) as $text) {
            $indent = strlen($text) - strlen(ltrim($text));
            if ($under !== null && $indent <= $under) {
                $under = null;
            }
            $key = preg_match('/^\s*(?:- )?([^:\s][^:]*):/', $text, $match) === 1 ? trim($match[1], '\'" ') : null;
            if ($under === null && $key !== null && in_array($key, $highlighted, true)) {
                $under = $indent;
                $lines[] = ['text' => $text, 'hl' => true];

                continue;
            }
            $lines[] = ['text' => $text, 'hl' => $under !== null];
        }

        return $lines;
    }
}
