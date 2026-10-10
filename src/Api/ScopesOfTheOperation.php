<?php

namespace App\Api;

use ApiPlatform\Metadata\HttpOperation;
use Symfony\Component\Security\Http\Authorization\OAuth2ScopeVoter;

/**
 * The scopes an operation of this API requires, read from the one place they are written: the "security"
 * expression of the operation itself (src/ApiResource/).
 *
 * Two things ask for them, and neither may keep a list of its own. What answers a refusal has to name the
 * scope that is missing in the challenge of RFC 6750 section 3.1 (TheScopeOfTheOperation), and the
 * documentation of the API has to say what an operation needs before anybody calls it
 * (ScopesInTheDocument). A scope written in three places would be three places that must agree.
 */
final readonly class ScopesOfTheOperation
{
    /**
     * The attributes of the OAuth2 scope voter, as the expression of an operation writes them.
     */
    private const string ATTRIBUTE_PATTERN = '/OAUTH2_SCOPE\([^)]*\)/';

    /**
     * The attributes the expression of this operation votes on, which are what a denial has to name.
     *
     * @return list<string>
     */
    public static function attributesOf(HttpOperation $operation): array
    {
        if (0 === (int) preg_match_all(self::ATTRIBUTE_PATTERN, (string) $operation->getSecurity(), $matches)) {
            return [];
        }

        return array_values(array_filter(
            $matches[0],
            static fn (string $attribute): bool => [] !== (OAuth2ScopeVoter::getRequiredScopes($attribute) ?? []),
        ));
    }

    /**
     * The scopes themselves, in the order the expression names them.
     *
     * @return list<string>
     */
    public static function of(HttpOperation $operation): array
    {
        $scopes = [];
        foreach (self::attributesOf($operation) as $attribute) {
            foreach (OAuth2ScopeVoter::getRequiredScopes($attribute) ?? [] as $scope) {
                $scopes[] = $scope;
            }
        }

        return array_values(array_unique($scopes));
    }
}
