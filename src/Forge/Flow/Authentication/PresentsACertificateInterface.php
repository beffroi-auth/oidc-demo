<?php

declare(strict_types=1);

namespace App\Forge\Flow\Authentication;

use App\Forge\BuiltClient;

/**
 * A method whose credential is the certificate presented on the connection (RFC 8705 §2): the forge draws
 * one, registers what names it, and every request of that client goes to the endpoints of the provider
 * that ask for a certificate (RFC 8705 §5).
 */
interface PresentsACertificateInterface extends ClientAuthenticationInterface
{
    /**
     * What the registration of such a client carries so that the provider recognises the certificate
     * (RFC 8705 §2.1.2 for a name it pins, §2.2 for a key it published).
     *
     * @return array<string, mixed>
     */
    public function registration(?string $subjectName): array;

    /**
     * The options that put the certificate of this client on a connection, for every request it makes and
     * not only for the ones it authenticates: RFC 8705 §3 binds the tokens of such a client to that
     * certificate whether it asked for it or not, so a request presenting the token and not the
     * certificate is refused. UserInfo is such a request, and it carries no client authentication at all.
     *
     * @return array<string, string>
     *
     * @throws \App\Forge\ForgeException when the client holds no certificate
     */
    public function transport(BuiltClient $client): array;
}
