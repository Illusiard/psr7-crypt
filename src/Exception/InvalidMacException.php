<?php

namespace Illusiard\Psr7Crypt\Exception;

class InvalidMacException extends Psr7CryptException
{
    public static function create(): self
    {
        return new self('Media MAC validation failed.');
    }
}
