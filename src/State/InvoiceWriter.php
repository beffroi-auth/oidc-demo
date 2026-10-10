<?php

namespace App\State;

use ApiPlatform\Metadata\Operation;
use ApiPlatform\State\ProcessorInterface;
use App\Api\PresentedToken;
use App\ApiResource\Invoice;
use App\Invoice\InvoiceBook;

/**
 * An invoice written into the book of the subject the access token names, which is what the scope
 * "invoices.write" allows. The demonstration asks the provider for "invoices.read" and "invoices.pay"
 * and never for this one, so this processor runs in a walk that asks for it and nowhere else.
 *
 * @implements ProcessorInterface<Invoice, Invoice>
 */
final readonly class InvoiceWriter implements ProcessorInterface
{
    public function __construct(
        private InvoiceBook $book,
        private PresentedToken $token,
    ) {
    }

    public function process(mixed $data, Operation $operation, array $uriVariables = [], array $context = []): Invoice
    {
        if (!$data instanceof Invoice) {
            throw new \LogicException(sprintf('This processor writes a %s, "%s" given.', Invoice::class, get_debug_type($data)));
        }

        return $this->book->add($this->token->subject(), $data);
    }
}
