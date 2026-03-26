<?php

namespace Illusiard\Psr7Crypt\Exception;

class EncryptionException extends Psr7CryptException
{
    public static function forOpenSslFailure(): self
    {
        return new self('OpenSSL failed to encrypt the provided plaintext chunk.');
    }
}
