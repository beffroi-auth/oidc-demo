<?php

namespace App\ApiResource;

use ApiPlatform\Metadata\ApiProperty;
use ApiPlatform\Metadata\ApiResource;
use ApiPlatform\Metadata\Post;
use App\State\PaymentProcessor;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * The payment of one invoice: the operation "invoices.pay" allows, and the one that tells this API from
 * the six routes of /api/ next to it. Those answer who the token names; this one changes something, and
 * what decides whether it may is the scope the provider granted and nothing this application stores.
 *
 * It is a resource of its own rather than a PATCH of the invoice, because paying is not editing: the
 * scope that allows it is not the scope that allows a write, and the operation of a resource is where
 * API Platform carries that difference.
 */
#[ApiResource(
    shortName: 'Payment',
    description: 'The payment of one invoice',
    uriTemplate: '/invoices/{reference}/payments',
    uriVariables: ['reference'],
    operations: [
        new Post(
            security: "is_granted('OAUTH2_SCOPE(invoices.pay)')",
            processor: PaymentProcessor::class,
            status: 201,
        ),
    ],
)]
final class Payment
{
    public function __construct(
        /**
         * The amount the client means to move, which has to be the amount of the invoice: a payment
         * that names another figure is refused rather than rounded to what is owed.
         */
        #[Assert\NotBlank]
        #[Assert\Regex('/^(0|[1-9][0-9]{0,12})(\.[0-9]{1,2})?$/')]
        public string $amount = '',
        #[ApiProperty(writable: false, description: 'The invoice that was paid')]
        public ?string $reference = null,
        #[ApiProperty(writable: false)]
        public ?string $paidAt = null,
    ) {
    }
}
