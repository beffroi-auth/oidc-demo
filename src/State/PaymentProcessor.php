<?php

namespace App\State;

use ApiPlatform\Metadata\Operation;
use ApiPlatform\State\ProcessorInterface;
use App\Api\PresentedToken;
use App\ApiResource\Payment;
use App\Invoice\InvoiceBook;
use Psr\Clock\ClockInterface;

/**
 * The payment of one invoice of the subject the access token names, which is what the scope
 * "invoices.pay" allows.
 *
 * @implements ProcessorInterface<Payment, Payment>
 */
final readonly class PaymentProcessor implements ProcessorInterface
{
    public function __construct(
        private InvoiceBook $book,
        private PresentedToken $token,
        private ClockInterface $clock,
    ) {
    }

    public function process(mixed $data, Operation $operation, array $uriVariables = [], array $context = []): Payment
    {
        if (!$data instanceof Payment) {
            throw new \LogicException(sprintf('This processor pays an invoice from a %s, "%s" given.', Payment::class, get_debug_type($data)));
        }

        $reference = (string) ($uriVariables['reference'] ?? '');
        $invoice = $this->book->pay($this->token->subject(), $reference, $data->amount, $this->clock->now());

        return new Payment(amount: $invoice->amount, reference: $invoice->reference, paidAt: $invoice->paidAt);
    }
}
