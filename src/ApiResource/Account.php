<?php

namespace App\ApiResource;

use ApiPlatform\Metadata\ApiProperty;
use ApiPlatform\Metadata\ApiResource;
use ApiPlatform\Metadata\Get;
use App\State\AccountProvider;

/**
 * Who the access token names, and how this API came to believe it: the subject, the scopes the token was
 * granted, and the client it was issued to, all of it read from what the firewall verified and nothing of
 * it stored here.
 *
 * It is behind "profile", a scope of OIDC Core section 5.4 the demonstration already asks for, so that
 * the API has one operation whose scope was not invented for it.
 */
#[ApiResource(
    shortName: 'Account',
    description: 'The subject the access token names, and how this API checked it',
    operations: [
        new Get(
            uriTemplate: '/account',
            security: "is_granted('OAUTH2_SCOPE(profile)')",
            provider: AccountProvider::class,
        ),
    ],
)]
final class Account
{
    public function __construct(
        #[ApiProperty(identifier: true, description: 'The "sub" of the token')]
        public string $sub = '',
        /**
         * @var list<string>
         */
        #[ApiProperty(description: 'The scopes this token was granted')]
        public array $scope = [],
        #[ApiProperty(description: 'The client the token was issued to')]
        public ?string $clientId = null,
        #[ApiProperty(description: 'How this API decided the token was usable')]
        public string $checkedBy = '',
    ) {
    }
}
