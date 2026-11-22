<?php

declare(strict_types=1);

namespace App\Showcase\Reference;

use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;

/**
 * The session the "main" firewall opened with oidc_login, when there is one: the token of the forge holds
 * an OIDC user too, and only the one oidc_login wrote carries its ID token.
 */
final readonly class MainSession
{
    public function __construct(
        private Security $security,
    ) {
    }

    public function token(): ?TokenInterface
    {
        $token = $this->security->getToken();

        return $token !== null && $token->hasAttribute('oidc_id_token') && is_string($token->getAttribute('oidc_id_token'))
            ? $token
            : null;
    }
}
