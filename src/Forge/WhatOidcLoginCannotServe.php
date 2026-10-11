<?php

declare(strict_types=1);

namespace App\Forge;

/**
 * What a composition would ask of Symfony's own authenticator that it cannot do yet, named by the item of
 * the status document that tracks it.
 *
 * This is the one thing the forge shows that the ladder of rungs could not: a client is composed, and the
 * page says whether `oidc_login` would serve that very client, or which gap stops it. A composition that
 * hits none of them is one a Symfony application reaches with configuration alone, which is what the
 * reference client of the "main" firewall is there to prove.
 *
 * The four items below are a copy, and the document they are copied from is where they are maintained:
 * `docs/specs/symfony-oauth-oidc-status.md` of the design repository, which is dated throughout and says
 * for each one what has merged upstream. An item merged there is deleted here, never left to say
 * something that stopped being true.
 */
final readonly class WhatOidcLoginCannotServe
{
    /**
     * @return list<array{code: string, what: string, why: string}>
     */
    public function of(Composition $composition): array
    {
        $gaps = [];

        if ($composition->request->pushed || $composition->request->isSignedAsARequestObject() || $composition->request->isSigned()) {
            $gaps[] = [
                'code' => 'RP-04',
                'what' => 'RFC 9126, RFC 9101, JARM',
                'why' => 'the authenticator puts the request in the URL and never signs it, and it reads an answer that is never one signed parameter',
            ];
        }
        if ($composition->documents->idToken->isEncrypted()) {
            $gaps[] = [
                'code' => 'RP-05',
                'what' => 'OIDC Core §3.1.3.7',
                'why' => 'the authenticator verifies a signature and opens no JWE, and a firewall publishes no key for one to be encrypted to',
            ];
        }
        if ($composition->documents->userInfo->signing !== null || $composition->documents->userInfo->isEncrypted()) {
            $gaps[] = [
                'code' => 'RP-06',
                'what' => 'OIDC Core §5.3.2',
                'why' => 'the authenticator reads the UserInfo answer as JSON, so an "application/jwt" one is not read at all',
            ];
        }
        if ($composition->logout->frontChannel) {
            $gaps[] = [
                'code' => 'RP-07',
                'what' => 'Front-Channel Logout 1.0',
                'why' => 'the back channel has merged upstream and the front channel has not, so an application writes that route itself',
            ];
        }

        return $gaps;
    }
}
