<?php

declare(strict_types=1);

namespace App\Forge\Flow\Authentication;

use App\Forge\BuiltClient;

/**
 * How a client of the forge proves it is itself on a request to the provider (RFC 6749 §2.3, RFC 7523
 * §2.2, RFC 8705 §2): one class per method the provider announces, each naming itself as the method is
 * named in a registration.
 *
 * A method is added by writing one of these and wiring it, never by a case added to something that
 * already exists: that is what lets the form of the forge offer what is wired rather than a list kept
 * beside it.
 */
interface ClientAuthenticationInterface
{
    /**
     * The name a registration carries in "token_endpoint_auth_method" (RFC 7591 §2).
     */
    public function name(): string;

    /**
     * What the page of a built client says of this method, in one sentence.
     */
    public function describe(): string;

    /**
     * The options of a request to an endpoint of the provider, with the credential of this client in
     * them: a header, two parameters of the body, or the certificate of the connection.
     *
     * @param array<string, mixed> $options
     *
     * @return array<string, mixed>
     *
     * @throws \App\Forge\ForgeException when the client holds not what this method needs
     */
    public function apply(BuiltClient $client, array $options): array;
}
