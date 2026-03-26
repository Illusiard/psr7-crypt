<?php

namespace Illusiard\Psr7Crypt\ValueObject;

use Illusiard\Psr7Crypt\Exception\InvalidMediaKeyLengthException;

final readonly class MediaKey
{
    public const int LENGTH = 32;

    public function __construct(
        private string $value
    ) {
        $actualLength = strlen($this->value);

        if ($actualLength !== self::LENGTH) {
            throw InvalidMediaKeyLengthException::forExpectedLength(self::LENGTH, $actualLength);
        }
    }

    public function getValue(): string
    {
        return $this->value;
    }
}
