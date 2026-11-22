<?php

namespace App\State;

use ApiPlatform\Metadata\Operation;
use ApiPlatform\State\ProviderInterface;
use App\Api\PresentedToken;
use App\ApiResource\Account;

/**
 * Who the token names, and how this API came to believe it: verified offline when it is addressed to this
 * API, or described by the provider, whose answer the firewall keeps a few seconds (config/services.yaml).
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
            checkedBy: str_starts_with($this->token->checkedBy(), 'introspected')
                ? sprintf('%s, the answer of an active token kept at most %d seconds', $this->token->checkedBy(), $this->introspectionCacheTtl)
                : $this->token->checkedBy(),
        );
    }
}
