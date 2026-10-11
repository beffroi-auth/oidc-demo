<?php

declare(strict_types=1);

namespace App\Forge\Flow\Binding;

use App\Forge\BuiltClient;

/**
 * What the access token of a client is bound to: nothing, which is a bearer token anybody who holds it
 * can spend (RFC 6750 §1.2), a key the client proves at every request (RFC 9449), or the certificate it
 * presents on the connection (RFC 8705 §3).
 *
 * One class per kind, each naming itself. What a kind needs between the two requests of a login it draws
 * itself, and what it puts on a request it puts there itself, so neither the flow nor the page ever asks
 * what kind it is holding.
 */
interface TokenBindingInterface
{
    public function name(): string;

    public function describe(): string;

    /**
     * What the flow has to remember for this binding from the start of a login to its end, drawn here:
     * the key of a proof is one, a certificate is nothing, the client already holding it.
     *
     * @return array<string, mixed>
     */
    public function remember(?string $algorithm): array;

    /**
     * RFC 8705 §5: whether the requests of this client go to the endpoints of the provider that ask for a
     * certificate rather than to the ordinary ones.
     */
    public function needsTheCertificateEndpoints(): bool;

    /**
     * The scheme the access token is presented under (RFC 6750 §2.1, RFC 9449 §7.1).
     */
    public function scheme(): string;

    /**
     * The options of a request to the provider, with what this binding has to prove on it.
     *
     * @param array<string, mixed> $options
     * @param array<string, mixed> $remembered
     *
     * @return array<string, mixed>
     *
     * @throws \App\Forge\ForgeException when the client holds not what this binding needs
     */
    public function apply(string $method, string $url, array $options, array $remembered, BuiltClient $client, ?string $accessToken = null): array;

    /**
     * What the token is bound to, as the provider names it in the "cnf" of the token it issued (RFC 9449
     * §6.1, RFC 8705 §3.1), so that the page can compare the two. Null for a token bound to nothing.
     *
     * @param array<string, mixed> $remembered
     */
    public function confirmation(array $remembered, BuiltClient $client): ?string;
}
