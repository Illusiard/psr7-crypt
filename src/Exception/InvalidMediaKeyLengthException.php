<?php

namespace Illusiard\Psr7Crypt\Exception;

class InvalidMediaKeyLengthException extends Psr7CryptException
{
    public static function forExpectedLength(int $expectedLength, int $actualLength): self
    {
        return new self(
            sprintf(
                'Media key must be %d bytes long, %d bytes given.',
                $expectedLength,
                $actualLength
            )
        );
    }
}
