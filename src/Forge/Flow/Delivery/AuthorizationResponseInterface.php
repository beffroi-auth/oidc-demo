<?php

declare(strict_types=1);

namespace App\Forge\Flow\Delivery;

use App\Forge\BuiltClient;
use Symfony\Component\HttpFoundation\Request;

/**
 * How the answer to an authorization request reaches the client: in the query of the redirection (OAuth
 * 2.0 Multiple Response Type Encoding Practices §2.1), posted back by a page of the provider (Form Post
 * Response Mode §2), or as one signed parameter in either of those (JARM §4).
 *
 * One class per shape the answer takes, each naming the response modes it answers to: the provider
 * resolves "jwt" to the mode of the response type (JARM §4.3), so one shape answers to two names rather
 * than being written twice.
 */
interface AuthorizationResponseInterface
{
    /**
     * The names a composition may carry in "response_mode" for this shape.
     *
     * @return list<string>
     */
    public function names(): array;

    public function describe(): string;

    /**
     * Whether the answer of this shape is one the provider signed, which carries inside the signature
     * what RFC 9207 §2 puts beside an unsigned one: a shape that says so has already checked the issuer
     * by the time it hands the parameters over.
     */
    public function isSigned(): bool;

    /**
     * Whether this shape comes back on a POST, which is what decides the method the callback route of a
     * built client answers.
     */
    public function isPosted(): bool;

    /**
     * The parameters of the answer, read off the request the browser made and verified as far as the
     * shape allows: a signed answer is verified against the keys of the provider before anything in it
     * is looked at, so that what the client acts on is what the provider said and not what the browser
     * carried.
     *
     * @return array{parameters: array<string, mixed>, carried: string, payload: string|null}
     *
     * @throws \App\Forge\ForgeException when the answer is not of this shape, or does not verify
     */
    public function read(Request $request, BuiltClient $client): array;
}
