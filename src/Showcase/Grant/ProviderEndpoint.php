<?php

declare(strict_types=1);

namespace App\Showcase\Grant;

use App\Forge\ForgeException;
use App\Forge\Offer;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * A request a client makes to an endpoint of the provider without any browser: a form posted to the
 * endpoint the discovery document names, the client authenticated with the secret it was issued
 * (RFC 6749 §2.3.1) or, a public client, naming itself (§2.3).
 */
final readonly class ProviderEndpoint
{
    public function __construct(
        private HttpClientInterface $httpClient,
        private Offer $offer,
    ) {
    }

    /**
     * @param array<string, string> $form
     *
     * @return array{status: int, body: array<string, mixed>}
     *
     * @throws ForgeException when the provider names no such endpoint or answers no JSON object
     */
    public function post(string $endpoint, array $form, string $clientId, ?string $secret): array
    {
        $url = $this->offer->endpoint($endpoint);
        $options = ['max_redirects' => 0, 'body' => $form];
        if ($secret === null) {
            $options['body']['client_id'] = $clientId;
        } else {
            $options['auth_basic'] = [rawurlencode($clientId), rawurlencode($secret)];
        }

        try {
            $response = $this->httpClient->request('POST', $url, $options);
            $status = $response->getStatusCode();
            $body = json_decode($response->getContent(false), true);
        } catch (TransportExceptionInterface $exception) {
            throw new ForgeException(sprintf('%s could not be reached: %s', $url, $exception->getMessage()), previous: $exception);
        }
        if (! is_array($body)) {
            throw new ForgeException(sprintf('%s answered %d, which is no JSON object.', $url, $status));
        }

        /** @var array<string, mixed> $body */
        return ['status' => $status, 'body' => $body];
    }
}
