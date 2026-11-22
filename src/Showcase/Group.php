<?php

declare(strict_types=1);

namespace App\Showcase;

final readonly class Group
{
    /**
     * @param list<Feature> $features
     */
    public function __construct(
        public string $title,
        public array $features,
    ) {
    }
}
