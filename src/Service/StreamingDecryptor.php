<?php

namespace Illusiard\Psr7Crypt\Service;

use HashContext;
use Illusiard\Psr7Crypt\Exception\DecryptionException;
use Illusiard\Psr7Crypt\Exception\InvalidEncryptedPayloadException;
use Illusiard\Psr7Crypt\Exception\InvalidMacException;
use Illusiard\Psr7Crypt\ValueObject\ExpandedMediaKey;

final class StreamingDecryptor
{
    public const int BLOCK_SIZE           = 16;
    public const int TRUNCATED_MAC_LENGTH = 10;

    private string $encryptedBuffer = '';

    private string $pendingPlaintext = '';

    private string $currentIv;

    private bool $isFinalized = false {
        get {
            return $this->isFinalized;
        }
    }

    private HashContext $macContext;

    public function __construct(
        private readonly ExpandedMediaKey $expandedMediaKey
    )
    {
        $this->currentIv  = $this->expandedMediaKey->getIv();
        $this->macContext = hash_init('sha256', HASH_HMAC, $this->expandedMediaKey->getMacKey());
        hash_update($this->macContext, $this->expandedMediaKey->getIv());
    }

    public function appendEncryptedData(string $encryptedData): string
    {
        if ($this->isFinalized || $encryptedData === '') {
            return '';
        }

        $this->encryptedBuffer .= $encryptedData;
        $processableLength     = $this->getProcessableCiphertextLength();

        if ($processableLength === 0) {
            return '';
        }

        $ciphertext            = substr($this->encryptedBuffer, 0, $processableLength);
        $this->encryptedBuffer = substr($this->encryptedBuffer, $processableLength);

        return $this->bufferReleasedPlaintext($this->decryptCiphertextChunk($ciphertext));
    }

    public function finalize(): string
    {
        if ($this->isFinalized) {
            return '';
        }

        if (strlen($this->encryptedBuffer) < self::TRUNCATED_MAC_LENGTH + self::BLOCK_SIZE) {
            throw InvalidEncryptedPayloadException::forInsufficientLength();
        }

        $ciphertext  = substr($this->encryptedBuffer, 0, -self::TRUNCATED_MAC_LENGTH);
        $providedMac = substr($this->encryptedBuffer, -self::TRUNCATED_MAC_LENGTH);

        if ($ciphertext === '' || strlen($ciphertext) % self::BLOCK_SIZE !== 0) {
            throw InvalidEncryptedPayloadException::forInvalidCiphertextLength();
        }

        hash_update($this->macContext, $ciphertext);
        $expectedMac = substr(hash_final($this->macContext, true), 0, self::TRUNCATED_MAC_LENGTH);

        if (!hash_equals($expectedMac, $providedMac)) {
            throw InvalidMacException::create();
        }

        $decryptedFinalChunk = $this->decryptCiphertextChunkWithoutMacUpdate($ciphertext, true);
        $finalPlaintext      = $this->pendingPlaintext . $decryptedFinalChunk;

        $this->isFinalized      = true;
        $this->encryptedBuffer  = '';
        $this->pendingPlaintext = '';

        return $finalPlaintext;
    }

    private function getProcessableCiphertextLength(): int
    {
        $availableCiphertextLength = strlen($this->encryptedBuffer) - self::TRUNCATED_MAC_LENGTH - self::BLOCK_SIZE;

        if ($availableCiphertextLength < self::BLOCK_SIZE) {
            return 0;
        }

        return intdiv($availableCiphertextLength, self::BLOCK_SIZE) * self::BLOCK_SIZE;
    }

    private function decryptCiphertextChunk(string $ciphertext): string
    {
        hash_update($this->macContext, $ciphertext);

        return $this->decryptCiphertextChunkWithoutMacUpdate($ciphertext);
    }

    private function decryptCiphertextChunkWithoutMacUpdate(string $ciphertext, bool $useOpenSslPadding = false): string
    {
        $plaintext = openssl_decrypt(
            $ciphertext,
            'aes-256-cbc',
            $this->expandedMediaKey->getCipherKey(),
            $useOpenSslPadding ? OPENSSL_RAW_DATA : OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $this->currentIv
        );

        if (!is_string($plaintext)) {
            throw DecryptionException::forOpenSslFailure();
        }

        $this->currentIv = substr($ciphertext, -self::BLOCK_SIZE);

        return $plaintext;
    }

    private function bufferReleasedPlaintext(string $plaintext): string
    {
        if ($plaintext === '') {
            return '';
        }

        $combinedPlaintext = $this->pendingPlaintext . $plaintext;

        if (strlen($combinedPlaintext) <= self::BLOCK_SIZE) {
            $this->pendingPlaintext = $combinedPlaintext;

            return '';
        }

        $releaseLength          = strlen($combinedPlaintext) - self::BLOCK_SIZE;
        $releasedPlaintext      = substr($combinedPlaintext, 0, $releaseLength);
        $this->pendingPlaintext = substr($combinedPlaintext, $releaseLength);

        return $releasedPlaintext;
    }

}
