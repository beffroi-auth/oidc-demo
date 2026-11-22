<?php

namespace App\Api\Console;

/**
 * What the page of /api-calls offers, in one place: the five operations the API serves, each with the scope
 * its token has to carry and the one thing it shows.
 *
 * Two of them are there for what they refuse rather than for what they return: a write, which the client of
 * this demonstration never asks the scope for, and the same payment twice, which the book of invoices
 * refuses because an invoice is not paid twice.
 */
final readonly class CallsOfThePage
{
    /**
     * The invoice the demonstration pays, which is the one "castor demo --rar" asks a detail about, for the
     * amount that detail bounds.
     */
    public const string INVOICE = 'INV-4711';

    public const string AMOUNT = '45.00';

    /**
     * @return list<ApiCall>
     */
    public function all(): array
    {
        return [
            new ApiCall(
                key: 'account',
                label: 'Who the token names',
                method: 'GET',
                path: '/api/v1/account',
                scope: 'invoices.read',
                says: 'The subject, the scopes the provider granted and the client the token was issued to, as the introspection response described it.',
            ),
            new ApiCall(
                key: 'invoices',
                label: 'The invoices',
                method: 'GET',
                path: '/api/v1/invoices',
                scope: 'invoices.read',
                says: 'The book of whoever the token names, and of nobody else.',
            ),
            new ApiCall(
                key: 'invoice',
                label: 'One invoice',
                method: 'GET',
                path: '/api/v1/invoices/' . self::INVOICE,
                scope: 'invoices.read',
                says: 'The invoice the payment below pays, before and after it is paid.',
            ),
            new ApiCall(
                key: 'pay',
                label: 'Pay it',
                method: 'POST',
                path: '/api/v1/invoices/' . self::INVOICE . '/payments',
                scope: 'invoices.pay',
                says: 'The one operation that changes something. Played twice, the second answers 409: an invoice is not paid twice.',
                body: ['amount' => self::AMOUNT],
            ),
            new ApiCall(
                key: 'write',
                label: 'Write an invoice',
                method: 'POST',
                path: '/api/v1/invoices',
                scope: 'invoices.write',
                says: 'Refused with 403 and the "insufficient_scope" challenge of RFC 6750 §3.1: the client of this demonstration registered that scope and never asks for it, so the token never carries it.',
                body: ['reference' => 'INV-9000', 'label' => 'Written from the page', 'amount' => '10.00', 'currency' => 'EUR'],
            ),
        ];
    }
}
