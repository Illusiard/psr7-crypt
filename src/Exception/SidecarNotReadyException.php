<?php

namespace Illusiard\Psr7Crypt\Exception;

class SidecarNotReadyException extends Psr7CryptException
{
    public static function create(): self
    {
        return new self('Sidecar is not available until encryption is finalized.');
    }
}
