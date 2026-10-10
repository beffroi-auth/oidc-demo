<?php

namespace App\Invoice;

use App\ApiResource\Invoice;
use Psr\Cache\CacheItemPoolInterface;
use Symfony\Component\HttpKernel\Exception\ConflictHttpException;
use Symfony\Component\HttpKernel\Exception\UnprocessableEntityHttpException;

/**
 * The invoices of one subject, kept in the cache pool of the application and in no database: the
 * demonstration has no Doctrine entity and this API adds none. What it is for is what a request may
 * read and change, so that a scope is felt on something rather than asserted on a page.
 *
 * A book belongs to the "sub" the access token names, which is the only thing the API knows of whoever
 * holds it: two users signed in on the same provider read two books, and nothing of one reaches the
 * other.
 *
 * INV-4711 is the invoice `castor demo --rar` asks to pay, with the amount that walk asks for: a scope
 * says a kind of thing, "invoices.pay" meaning any of them, and a rich authorization request names this
 * one and how much of it. The two readings meet on the same invoice on purpose.
 */
final readonly class InvoiceBook
{
    private const string CACHE_PREFIX = 'demo.invoices.';

    /**
     * The book a subject starts with, written once, the day it is first read.
     *
     * @var list<array{reference: string, label: string, amount: string, currency: string, paid: bool}>
     */
    private const array OPENING = [
        ['reference' => 'INV-4711', 'label' => 'Hosting, September', 'amount' => '45.00', 'currency' => 'EUR', 'paid' => false],
        ['reference' => 'INV-4712', 'label' => 'Domain name, one year', 'amount' => '12.50', 'currency' => 'EUR', 'paid' => true],
        ['reference' => 'INV-4713', 'label' => 'Support, September', 'amount' => '120.00', 'currency' => 'EUR', 'paid' => false],
    ];

    public function __construct(
        private CacheItemPoolInterface $pool,
    ) {
    }

    /**
     * @return list<Invoice>
     */
    public function of(string $subject): array
    {
        return array_values($this->book($subject));
    }

    public function one(string $subject, string $reference): ?Invoice
    {
        return $this->book($subject)[$reference] ?? null;
    }

    /**
     * An invoice this subject did not have, written under the reference it names.
     */
    public function add(string $subject, Invoice $invoice): Invoice
    {
        $book = $this->book($subject);
        if (isset($book[$invoice->reference])) {
            throw new ConflictHttpException(sprintf('The invoice "%s" is already in this book.', $invoice->reference));
        }

        $book[$invoice->reference] = $invoice;
        $this->write($subject, $book);

        return $invoice;
    }

    /**
     * The payment of one invoice, which is what "invoices.pay" allows and what the book records: the
     * amount has to be the amount of the invoice, and an invoice already paid is not paid twice.
     */
    public function pay(string $subject, string $reference, string $amount, \DateTimeImmutable $at): Invoice
    {
        $book = $this->book($subject);
        $invoice = $book[$reference] ?? throw new UnprocessableEntityHttpException(sprintf('No invoice "%s" in this book.', $reference));
        if (null !== $invoice->paidAt) {
            throw new ConflictHttpException(sprintf('The invoice "%s" was paid on %s.', $reference, $invoice->paidAt));
        }
        if ($amount !== $invoice->amount) {
            throw new UnprocessableEntityHttpException(sprintf('The invoice "%s" is for %s %s.', $reference, $invoice->amount, $invoice->currency));
        }

        $book[$reference] = $invoice->paidAt($at);
        $this->write($subject, $book);

        return $book[$reference];
    }

    /**
     * @return array<string, Invoice>
     */
    private function book(string $subject): array
    {
        $item = $this->pool->getItem(self::key($subject));
        if ($item->isHit()) {
            /** @var array<string, Invoice> $book */
            $book = $item->get();

            return $book;
        }

        $book = [];
        foreach (self::OPENING as $opening) {
            $book[$opening['reference']] = new Invoice(
                reference: $opening['reference'],
                label: $opening['label'],
                amount: $opening['amount'],
                currency: $opening['currency'],
                paidAt: $opening['paid'] ? '2026-09-01T09:00:00+00:00' : null,
            );
        }
        $this->write($subject, $book);

        return $book;
    }

    /**
     * @param array<string, Invoice> $book
     */
    private function write(string $subject, array $book): void
    {
        $item = $this->pool->getItem(self::key($subject));
        $item->set($book);
        $this->pool->save($item);
    }

    /**
     * The identifier of the subject is not a key of a cache pool: it is hashed, as the introspection
     * cache of the firewall hashes the token it remembers.
     */
    private static function key(string $subject): string
    {
        return self::CACHE_PREFIX . hash('sha256', $subject);
    }
}
