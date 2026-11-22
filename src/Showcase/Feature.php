<?php

declare(strict_types=1);

namespace App\Showcase;

final readonly class Feature
{
    public function __construct(
        public string $slug,
        public FeatureClientInterface $client,
    ) {
    }
}
