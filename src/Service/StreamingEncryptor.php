<?php

namespace Illusiard\Psr7Crypt\Service;

use HashContext;
use Illusiard\Psr7Crypt\Exception\EncryptionException;
use Illusiard\Psr7Crypt\Exception\SidecarNotReadyException;
use Illusiard\Psr7Crypt\ValueObject\ExpandedMediaKey;
use Illusiard\Psr7Crypt\ValueObject\Sidecar;

final class StreamingEncryptor
{
    public const int BLOCK_SIZE           = 16;
    public const int TRUNCATED_MAC_LENGTH = 10;

    private string $plainBuffer = '';

    private string $currentIv;

    private bool $isFinalized = false {
            get {
                return $this->isFinalized;
            }
        }

    private HashContext $macContext;

    public function __construct(
        private readonly ExpandedMediaKey    $expandedMediaKey,
        private readonly ?SidecarAccumulator $sidecarAccumulator = null
    )
    {
        $this->currentIv  = $this->expandedMediaKey->getIv();
        $this->macContext = hash_init('sha256', HASH_HMAC, $this->expandedMediaKey->getMacKey());
        hash_update($this->macContext, $this->expandedMediaKey->getIv());

        $this->sidecarAccumulator?->appendInitializationVector($this->expandedMediaKey->getIv());
    }

    public function appendPlaintext(string $plaintext): string
    {
        if ($this->isFinalized || $plaintext === '') {
            return '';
        }

        $this->plainBuffer   .= $plaintext;
        $completeBlockLength = intdiv(strlen($this->plainBuffer), self::BLOCK_SIZE) * self::BLOCK_SIZE;

        if ($completeBlockLength === 0) {
            return '';
        }

        $plaintextToEncrypt = substr($this->plainBuffer, 0, $completeBlockLength);
        $this->plainBuffer  = substr($this->plainBuffer, $completeBlockLength);

        return $this->encryptChunk($plaintextToEncrypt);
    }

    public function finalize(): string
    {
        if ($this->isFinalized) {
            return '';
        }

        $paddingLength = self::BLOCK_SIZE - (strlen($this->plainBuffer) % self::BLOCK_SIZE);

        if ($paddingLength === 0) {
            $paddingLength = self::BLOCK_SIZE;
        }

        $finalPlaintextBlock = $this->plainBuffer . str_repeat(chr($paddingLength), $paddingLength);
        $ciphertext          = $this->encryptChunk($finalPlaintextBlock);
        $mac                 = substr(hash_final($this->macContext, true), 0, self::TRUNCATED_MAC_LENGTH);

        $this->plainBuffer = '';
        $this->isFinalized = true;

        if ($this->sidecarAccumulator !== null) {
            $this->sidecarAccumulator->appendMessageAuthenticationCode($mac);
            $this->sidecarAccumulator->finalize();
        }

        return $ciphertext . $mac;
    }

    public function hasSidecar(): bool
    {
        return $this->sidecarAccumulator !== null;
    }

    public function isSidecarReady(): bool
    {
        return $this->sidecarAccumulator !== null && $this->sidecarAccumulator->isFinalized;
    }

    public function getSidecar(): ?Sidecar
    {
        if ($this->sidecarAccumulator === null) {
            return null;
        }

        if (!$this->sidecarAccumulator->isFinalized) {
            throw SidecarNotReadyException::create();
        }

        return $this->sidecarAccumulator->getSidecar();
    }

    private function encryptChunk(string $plaintext): string
    {
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-cbc',
            $this->expandedMediaKey->getCipherKey(),
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $this->currentIv
        );

        if (!is_string($ciphertext)) {
            throw EncryptionException::forOpenSslFailure();
        }

        $this->currentIv = substr($ciphertext, -self::BLOCK_SIZE);
        hash_update($this->macContext, $ciphertext);

        $this->sidecarAccumulator?->appendCiphertext($ciphertext);

        return $ciphertext;
    }
}
