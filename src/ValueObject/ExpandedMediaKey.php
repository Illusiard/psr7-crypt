<?php

namespace Illusiard\Psr7Crypt\ValueObject;

use Illusiard\Psr7Crypt\Exception\InvalidExpandedMediaKeyLengthException;

final readonly class ExpandedMediaKey
{
    public const int LENGTH            = 112;
    public const int IV_LENGTH         = 16;
    public const int CIPHER_KEY_LENGTH = 32;
    public const int MAC_KEY_LENGTH    = 32;
    public const int REF_KEY_LENGTH    = 32;

    public function __construct(
        private string $value
    )
    {
        $actualLength = strlen($this->value);

        if ($actualLength !== self::LENGTH) {
            throw InvalidExpandedMediaKeyLengthException::forExpectedLength(self::LENGTH, $actualLength);
        }
    }

    public function getValue(): string
    {
        return $this->value;
    }

    public function getIv(): string
    {
        return substr($this->value, 0, self::IV_LENGTH);
    }

    public function getCipherKey(): string
    {
        return substr($this->value, self::IV_LENGTH, self::CIPHER_KEY_LENGTH);
    }

    public function getMacKey(): string
    {
        return substr(
            $this->value,
            self::IV_LENGTH + self::CIPHER_KEY_LENGTH,
            self::MAC_KEY_LENGTH
        );
    }

    public function getRefKey(): string
    {
        return substr(
            $this->value,
            self::IV_LENGTH + self::CIPHER_KEY_LENGTH + self::MAC_KEY_LENGTH,
            self::REF_KEY_LENGTH
        );
    }
}
