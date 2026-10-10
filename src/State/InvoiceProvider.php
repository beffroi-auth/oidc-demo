<?php

namespace App\State;

use ApiPlatform\Metadata\CollectionOperationInterface;
use ApiPlatform\Metadata\Operation;
use ApiPlatform\State\ProviderInterface;
use App\Api\PresentedToken;
use App\ApiResource\Invoice;
use App\Invoice\InvoiceBook;

/**
 * The invoices of the subject the access token names, and of nobody else: a reference this subject does
 * not have is a 404 here, whatever another subject has under it.
 *
 * @implements ProviderInterface<Invoice>
 */
final readonly class InvoiceProvider implements ProviderInterface
{
    public function __construct(
        private InvoiceBook $book,
        private PresentedToken $token,
    ) {
    }

    public function provide(Operation $operation, array $uriVariables = [], array $context = []): iterable|Invoice|null
    {
        $subject = $this->token->subject();

        if ($operation instanceof CollectionOperationInterface) {
            return $this->book->of($subject);
        }

        return $this->book->one($subject, (string) ($uriVariables['reference'] ?? ''));
    }
}
