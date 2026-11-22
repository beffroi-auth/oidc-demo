<?php

declare(strict_types=1);

namespace App\Showcase\Reference;

use Symfony\Component\Yaml\Yaml;

/**
 * The security configuration of this application as it is written, read from the file itself, so that
 * the configuration a panel shows is the one that runs.
 */
final class SecurityConfiguration
{
    /**
     * @var array<string, mixed>|null
     */
    private ?array $security = null;

    public function __construct(
        private readonly string $file,
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function firewall(string $name): array
    {
        $firewalls = $this->security()['firewalls'] ?? [];
        $firewall = is_array($firewalls) ? ($firewalls[$name] ?? []) : [];

        /** @var array<string, mixed> $firewall */
        return is_array($firewall) ? $firewall : [];
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function accessRulesOf(string $path): array
    {
        $rules = $this->security()['access_control'] ?? [];
        $matching = [];
        foreach (is_array($rules) ? $rules : [] as $rule) {
            if (is_array($rule) && ($rule['path'] ?? null) === $path) {
                /** @var array<string, mixed> $rule */
                $matching[] = $rule;
            }
        }

        return $matching;
    }

    /**
     * @return array<string, mixed>
     */
    private function security(): array
    {
        if ($this->security === null) {
            $parsed = Yaml::parseFile($this->file);
            $security = is_array($parsed) ? ($parsed['security'] ?? []) : [];
            /** @var array<string, mixed> $security */
            $this->security = is_array($security) ? $security : [];
        }

        return $this->security;
    }
}
