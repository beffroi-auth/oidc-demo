<?php

declare(strict_types=1);

namespace App\Forge;

/**
 * A client of the forge as it exists at the provider: the handle its routes are written with, what the
 * provider answered to its registration (RFC 7591 §3.2.1), the material it holds, and the form it was
 * composed from, kept whole so that the composition is read back from it rather than stored a second
 * time, and so that the page can offer it again for editing.
 *
 * Its handle is the demonstration's and not the provider's: the redirect URI of a client has to be known
 * before it is registered, and the identifier the provider assigns is only known afterwards (RFC 7591
 * §3.2.1). So every URI of a built client carries its handle, and the handle names one registration at a
 * time: building the same preset again replaces the client it named.
 */
final readonly class BuiltClient
{
    /**
     * @param array<string, mixed> $form what was composed, as the form submitted it
     * @param array<string, mixed> $registration what was sent to the registration endpoint
     * @param array<string, mixed> $answer what the provider answered, its credentials taken out of it
     */
    public function __construct(
        public string $handle,
        public string $clientId,
        public ?string $clientSecret,
        public array $form,
        public array $registration,
        public array $answer,
        public Material $material,
        public int $builtAt,
    ) {
    }

    /**
     * RFC 7592 §2: the credential the provider issued for this client to read, replace and delete itself,
     * and the URI it does so at. A registration that answered neither leaves the client where it is: the
     * provider removes it on its own once it has gone unused (decision 0009).
     */
    public function registrationAccessToken(): ?string
    {
        $token = $this->answer['registration_access_token'] ?? null;

        return is_string($token) && $token !== '' ? $token : null;
    }

    public function registrationUri(): ?string
    {
        $uri = $this->answer['registration_client_uri'] ?? null;

        return is_string($uri) && $uri !== '' ? $uri : null;
    }

    public function name(): string
    {
        $name = $this->answer['client_name'] ?? $this->registration['client_name'] ?? null;

        return is_string($name) ? $name : $this->handle;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'handle' => $this->handle,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'form' => $this->form,
            'registration' => $this->registration,
            'answer' => $this->answer,
            'material' => $this->material->toArray(),
            'built_at' => $this->builtAt,
        ];
    }

    /**
     * @param array<string, mixed> $values
     *
     * @throws ForgeException when what was stored is not a built client
     */
    public static function fromArray(array $values): self
    {
        $handle = $values['handle'] ?? null;
        $clientId = $values['client_id'] ?? null;
        if (! is_string($handle) || ! is_string($clientId)) {
            throw new ForgeException('What the store holds under this handle is not a built client.');
        }

        /** @var array<string, mixed> $form */
        $form = is_array($values['form'] ?? null) ? $values['form'] : [];
        /** @var array<string, mixed> $registration */
        $registration = is_array($values['registration'] ?? null) ? $values['registration'] : [];
        /** @var array<string, mixed> $answer */
        $answer = is_array($values['answer'] ?? null) ? $values['answer'] : [];
        /** @var array<string, mixed> $material */
        $material = is_array($values['material'] ?? null) ? $values['material'] : [];

        return new self(
            $handle,
            $clientId,
            is_string($values['client_secret'] ?? null) ? $values['client_secret'] : null,
            $form,
            $registration,
            $answer,
            Material::fromArray($material),
            is_int($values['built_at'] ?? null) ? $values['built_at'] : 0,
        );
    }
}
