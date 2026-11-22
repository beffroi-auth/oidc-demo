<?php

declare(strict_types=1);

namespace App\Api;

use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\Authenticator\AccessTokenAuthenticator;

/**
 * What the API knows of the request: the access token as the firewall read it, in one place because
 * three state classes read it.
 *
 * Nothing is verified here and nothing could be. The firewall verified the token, itself or by asking the
 * provider (AddressedHereOrDescribed), before anything of this API ran, and what it obtained is on the
 * security token and on the request: the subject, the scopes the token was granted, its claims and how it
 * was checked. A request that reaches this class is a request that passed that.
 */
final readonly class PresentedToken
{
    public function __construct(
        private Security $security,
        private RequestStack $requests,
    ) {
    }

    /**
     * The "sub" of the token, which is whose invoices a request reads.
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

    /**
     * RFC 9068 §2.2 and RFC 7662 §2.2 name it the same: the client the token was issued to.
     */
    public function clientId(): ?string
    {
        $clientId = $this->checked()['claims']['client_id'] ?? null;

        return is_string($clientId) ? $clientId : null;
    }

    public function checkedBy(): string
    {
        return $this->checked()['how'] ?? 'unknown';
    }

    /**
     * @return array{how?: string, claims?: array<string, mixed>}
     */
    private function checked(): array
    {
        $checked = $this->requests->getCurrentRequest()?->attributes->get(AddressedHereOrDescribed::CHECKED);

        /** @var array{how?: string, claims?: array<string, mixed>} */
        return is_array($checked) ? $checked : [];
    }
}
