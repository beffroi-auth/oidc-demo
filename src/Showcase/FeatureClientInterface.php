<?php

declare(strict_types=1);

namespace App\Showcase;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * The client that faces a feature of the provider in the tree: what it is called, the one line that says
 * what it does, its configuration, whether it works, and how it is run.
 */
interface FeatureClientInterface
{
    public function title(): string;

    public function does(): string;

    public function view(): ClientView;

    /**
     * What the square of the tree shows: "ok" when the last run in this browser worked, "ko" when it
     * failed, "off" when the provider does not offer it, "idle" when it never ran.
     */
    public function status(): string;

    /**
     * The hidden fields the run form carries beside its button.
     *
     * @return array<string, string>
     */
    public function runFields(): array;

    /**
     * Starts the client, the browser coming back to $back once it is done.
     */
    public function run(Request $request, string $back): Response;
}
