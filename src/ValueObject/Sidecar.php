<?php

namespace Illusiard\Psr7Crypt\ValueObject;

use Illusiard\Psr7Crypt\Service\SidecarAccumulator;

final readonly class Sidecar
{
    public function __construct(
        private string $value
    )
    {
    }

    public function getValue(): string
    {
        return $this->value;
    }

    public function isEmpty(): bool
    {
        return $this->value === '';
    }

    public function getChunkCount(): int
    {
        return intdiv(strlen($this->value), SidecarAccumulator::TRUNCATED_MAC_LENGTH);
    }
}
