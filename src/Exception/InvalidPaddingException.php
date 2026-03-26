<?php

namespace Illusiard\Psr7Crypt\Exception;

class InvalidPaddingException extends Psr7CryptException
{
    public static function create(): self
    {
        return new self('Decrypted plaintext contains invalid PKCS#7 padding.');
    }
}
