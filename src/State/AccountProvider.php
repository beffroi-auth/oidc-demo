<?php

namespace App\State;

use ApiPlatform\Metadata\Operation;
use ApiPlatform\State\ProviderInterface;
use App\Api\PresentedToken;
use App\ApiResource\Account;

/**
 * Who the token names, as the provider described it, and how long this API is willing to go on believing
 * it: the lifetime is the one the firewall caches an introspection response for, read from the one place
 * it is written (config/services.yaml), so that the answer cannot say another figure than the firewall
 * applies.
 *
 * @implements ProviderInterface<Account>
 */
final readonly class AccountProvider implements ProviderInterface
{
    public function __construct(
        private PresentedToken $token,
        private int $introspectionCacheTtl,
    ) {
    }

    public function provide(Operation $operation, array $uriVariables = [], array $context = []): Account
    {
        return new Account(
            sub: $this->token->subject(),
            scope: $this->token->scopes(),
            clientId: $this->token->clientId(),
            checkedBy: sprintf(
                'introspection at the provider (RFC 7662), the answer of an active token kept at most %d seconds',
                $this->introspectionCacheTtl,
            ),
        );
    }
}
