<?php

namespace Illusiard\Psr7Crypt\Exception;

class DecryptionException extends Psr7CryptException
{
    public static function forOpenSslFailure(): self
    {
        return new self('OpenSSL failed to decrypt the provided ciphertext chunk.');
    }
}
