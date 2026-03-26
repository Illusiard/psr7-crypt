<?php

namespace Illusiard\Psr7Crypt\Exception;

class InvalidEncryptedPayloadException extends Psr7CryptException
{
    public static function forInsufficientLength(): self
    {
        return new self('Encrypted payload is too short to contain ciphertext and truncated MAC.');
    }

    public static function forInvalidCiphertextLength(): self
    {
        return new self('Encrypted payload contains ciphertext with an invalid AES block length.');
    }
}
