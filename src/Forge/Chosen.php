<?php

declare(strict_types=1);

namespace App\Forge;

/**
 * One value of a composition, read from what was submitted and held to what the provider offers. Every
 * family of a composition reads its members through here, so that a value nobody announced is refused in
 * one place and with one sentence, rather than in each family its own way.
 */
final readonly class Chosen
{
    /**
     * @param list<string> $among
     *
     * @throws ForgeException when the value is not one of them
     */
    public static function one(mixed $value, array $among, string $member): string
    {
        $name = is_string($value) ? $value : '';
        if (! in_array($name, $among, true)) {
            throw new ForgeException(sprintf(
                'The provider does not offer "%s" for "%s": it offers %s.',
                $name,
                $member,
                $among === [] ? 'nothing' : '"' . implode('", "', $among) . '"',
            ));
        }

        return $name;
    }

    /**
     * The same, for a member a composition may leave out: an empty submission is none of it.
     *
     * @param list<string> $among
     *
     * @throws ForgeException when the value is neither empty nor one of them
     */
    public static function orNone(mixed $value, array $among, string $member): ?string
    {
        if ($value === null || $value === '' || $value === 'none') {
            return null;
        }

        return self::one($value, $among, $member);
    }

    /**
     * @param list<string> $among
     *
     * @return list<string>
     *
     * @throws ForgeException when one of the values is not among them
     */
    public static function several(mixed $values, array $among, string $member): array
    {
        $chosen = [];
        foreach (is_array($values) ? $values : [] as $value) {
            $chosen[] = self::one($value, $among, $member);
        }

        return array_values(array_unique($chosen));
    }

    public static function asked(mixed $value): bool
    {
        return $value === true || $value === '1' || $value === 'on' || $value === 'yes';
    }
}
