<?php

declare(strict_types=1);

namespace App\Forge\Flow\Authentication;

use App\Forge\BuiltClient;
use App\Forge\ForgeException;

/**
 * Where the certificate of a built client is on disk: an HTTP client presents a file and not a string, so
 * what the store holds is written out under var/ the first time it is needed and read from there after.
 *
 * It is written under the handle of the client, so two built clients never present the same certificate,
 * and it is rewritten whenever what the store holds is not what the file holds: building a preset again
 * draws a new certificate under the same handle.
 */
final readonly class CertificateFiles
{
    public function __construct(
        private string $directory,
    ) {
    }

    /**
     * @return array{string, string} the certificate and the key it goes with
     *
     * @throws ForgeException when the client presents none, or the files cannot be written
     */
    public function of(BuiltClient $client): array
    {
        $certificate = $client->material->certificate;
        $key = $client->material->certificateKey;
        if ($certificate === null || $key === null) {
            throw new ForgeException('This client presents no certificate, so there is none to write out.');
        }

        return [
            $this->write(sprintf('%s.crt.pem', $client->handle), $certificate),
            $this->write(sprintf('%s.key.pem', $client->handle), $key),
        ];
    }

    /**
     * @throws ForgeException when the file cannot be written
     */
    private function write(string $name, string $contents): string
    {
        if (! is_dir($this->directory) && ! mkdir($this->directory, 0o700, true) && ! is_dir($this->directory)) {
            throw new ForgeException(sprintf('The forge cannot write under "%s".', $this->directory));
        }
        $path = $this->directory . '/' . $name;
        if (! is_file($path) || file_get_contents($path) !== $contents) {
            if (file_put_contents($path, $contents) === false) {
                throw new ForgeException(sprintf('The forge cannot write "%s".', $path));
            }
            chmod($path, 0o600);
        }

        return $path;
    }
}
