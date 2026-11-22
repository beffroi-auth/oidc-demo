<?php

declare(strict_types=1);

namespace App\Twig;

use Symfony\Component\Security\Core\User\OidcUser;
use Symfony\Component\Security\Core\User\UserInterface;
use Twig\Attribute\AsTwigFilter;

/**
 * What the top bar calls whoever is signed in, from the claims of OIDC Core §5.1: the name the provider gave
 * ("given_name", "family_name"), else an address it verified ("email" with "email_verified" true), and the
 * subject only when it gave neither. An address the provider did not verify names nobody.
 */
final readonly class SignedInName
{
    /**
     * A subject is a long opaque string, of which the top bar shows the start.
     */
    private const int SUBJECT_SHOWN = 18;

    #[AsTwigFilter('signed_in_name')]
    public function of(UserInterface $user): string
    {
        if (! $user instanceof OidcUser) {
            return $user->getUserIdentifier();
        }

        $name = implode(' ', array_filter(
            [$user->getGivenName(), $user->getFamilyName()],
            static fn (?string $part): bool => null !== $part && '' !== trim($part),
        ));
        if ('' !== $name) {
            return $name;
        }

        $email = $user->getEmail();
        if (true === $user->getEmailVerified() && null !== $email && '' !== $email) {
            return $email;
        }

        return mb_substr($user->getUserIdentifier(), 0, self::SUBJECT_SHOWN);
    }
}
