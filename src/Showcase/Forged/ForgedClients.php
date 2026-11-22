<?php

declare(strict_types=1);

namespace App\Showcase\Forged;

use App\Forge\BuiltClients;
use App\Forge\Forge;
use App\Forge\ForgeException;
use App\Forge\Offer;
use App\Forge\Presets;
use App\Showcase\Runs;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

final readonly class ForgedClients
{
    public function __construct(
        private Presets $presets,
        private Forge $forge,
        private BuiltClients $clients,
        private Offer $offer,
        private Runs $runs,
        private UrlGeneratorInterface $urls,
    ) {
    }

    /**
     * @throws ForgeException when no preset of that name is written down
     */
    public function of(string $preset): ForgedClient
    {
        return new ForgedClient(
            $this->presets->of($preset),
            $this->presets->of(Presets::BASELINE),
            $this->forge,
            $this->clients,
            $this->offer,
            $this->runs,
            $this->urls,
        );
    }
}
