<?php

namespace App\Api;

use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\User\OAuth2User;
use Symfony\Component\Security\Http\Authenticator\AccessTokenAuthenticator;

/**
 * What the API knows of the request: the access token as the provider described it, read in one place
 * because three state classes read it.
 *
 * Nothing is verified here and nothing could be. The firewall introspected the token (RFC 7662) before
 * anything of this API ran, and what it obtained is on the security token: the subject, the scopes the
 * provider says were granted, and the client the token was issued to. A request that reaches this class
 * is a request that passed that.
 */
final readonly class PresentedToken
{
    public function __construct(
        private Security $security,
    ) {
    }

    /**
     * The "sub" of the introspection response, which is whose invoices a request reads.
     */
    public function subject(): string
    {
        $subject = $this->security->getToken()?->getUserIdentifier();
        if (null === $subject || '' === $subject) {
            throw new AccessDeniedException('The request carries no access token this API could read a subject from.');
        }

        return $subject;
    }

    /**
     * @return list<string>
     */
    public function scopes(): array
    {
        $scopes = $this->security->getToken()?->getAttribute(AccessTokenAuthenticator::SCOPE_ATTRIBUTE) ?? [];

        return array_values(array_filter($scopes, static fn (mixed $scope): bool => is_string($scope)));
    }

    public function clientId(): ?string
    {
        $user = $this->security->getUser();

        return $user instanceof OAuth2User ? $user->clientId : null;
    }
}
