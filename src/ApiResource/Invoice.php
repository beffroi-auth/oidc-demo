<?php

namespace App\ApiResource;

use ApiPlatform\Metadata\ApiProperty;
use ApiPlatform\Metadata\ApiResource;
use ApiPlatform\Metadata\Get;
use ApiPlatform\Metadata\GetCollection;
use ApiPlatform\Metadata\Post;
use App\State\InvoiceProvider;
use App\State\InvoiceWriter;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * The invoices of whoever the access token names, served by API Platform under /api/v1.
 *
 * One scope per operation, and the firewall of this API knows nothing else of the request: the token is
 * described by the provider (RFC 7662) and the scopes it was granted are what the OAUTH2_SCOPE attribute
 * of Symfony votes on. A token granted "invoices.read" reads this collection and is refused the write
 * with the "insufficient_scope" challenge of RFC 6750 section 3.1, which is a 403 and not a 401: the
 * token is good, it was never granted that.
 *
 * What a scope cannot say is in the detail of a rich authorization request (RFC 9396), which names one
 * invoice and the most that may be moved: "castor demo --rar" asks for one on INV-4711 of this very
 * book, and nothing here reads it.
 */
#[ApiResource(
    shortName: 'Invoice',
    description: 'An invoice of the subject the access token names',
    operations: [
        new GetCollection(
            security: "is_granted('OAUTH2_SCOPE(invoices.read)')",
            provider: InvoiceProvider::class,
        ),
        new Get(
            security: "is_granted('OAUTH2_SCOPE(invoices.read)')",
            provider: InvoiceProvider::class,
        ),
        new Post(
            security: "is_granted('OAUTH2_SCOPE(invoices.write)')",
            processor: InvoiceWriter::class,
        ),
    ],
)]
final class Invoice
{
    public function __construct(
        #[ApiProperty(identifier: true, description: 'The reference of the invoice, which is its identifier here')]
        #[Assert\NotBlank]
        #[Assert\Regex('/^INV-[0-9]{4,}$/')]
        public ?string $reference = null,
        #[Assert\NotBlank]
        #[Assert\Length(max: 80)]
        public string $label = '',
        /**
         * The shape RFC 9396 section 9.1 writes an amount in, which is the shape the detail of --rar
         * carries: a decimal in a string, so that nothing is read as a float and nothing rounds.
         */
        #[Assert\NotBlank]
        #[Assert\Regex('/^(0|[1-9][0-9]{0,12})(\.[0-9]{1,2})?$/')]
        public string $amount = '0.00',
        #[Assert\Currency]
        public string $currency = 'EUR',
        #[ApiProperty(writable: false, description: 'When it was paid, or null; a payment is the operation of /invoices/{reference}/payments')]
        public ?string $paidAt = null,
    ) {
    }

    public function paidAt(\DateTimeImmutable $at): self
    {
        return new self($this->reference, $this->label, $this->amount, $this->currency, $at->format(\DateTimeInterface::ATOM));
    }
}
