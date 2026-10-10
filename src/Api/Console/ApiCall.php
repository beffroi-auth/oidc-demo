<?php

namespace App\Api\Console;

/**
 * One call the page of /api-calls offers: what it asks of the API, and what the access token has to carry
 * for the API to serve it.
 *
 * The scope is written here for what the page says, and the API enforces its own from the operation it
 * declares (src/ApiResource/): a call this page describes as needing "invoices.pay" and that the API would
 * serve without it would be a page that lies, which is what the walk of the provider compares.
 */
final readonly class ApiCall
{
    /**
     * @param array<string, mixed>|null $body what the call posts, or null for a call that posts nothing
     */
    public function __construct(
        public string $key,
        public string $label,
        public string $method,
        public string $path,
        public string $scope,
        public string $says,
        public ?array $body = null,
    ) {
    }

    /**
     * The same call as a command line, for whoever would rather read it than click it, and for a browser
     * that runs nothing: the token is the one the page holds, pasted where this says.
     */
    public function asCurl(string $origin): string
    {
        $parts = ['curl', '-i'];
        if ('GET' !== $this->method) {
            $parts[] = '-X ' . $this->method;
        }
        $parts[] = sprintf("'%s%s'", $origin, $this->path);
        $parts[] = "-H 'Accept: application/json'";
        $parts[] = "-H \"Authorization: Bearer \$TOKEN\"";
        if (null !== $this->body) {
            $parts[] = "-H 'Content-Type: application/json'";
            $parts[] = sprintf("-d '%s'", json_encode($this->body, \JSON_THROW_ON_ERROR | \JSON_UNESCAPED_SLASHES));
        }

        return implode(" \\\n  ", $parts);
    }
}
