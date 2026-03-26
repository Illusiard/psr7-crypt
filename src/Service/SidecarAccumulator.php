<?php

namespace Illusiard\Psr7Crypt\Service;

use Illusiard\Psr7Crypt\Exception\SidecarNotReadyException;
use Illusiard\Psr7Crypt\ValueObject\Sidecar;

final class SidecarAccumulator
{
    public const int CHUNK_SIZE           = 65536;
    public const int OVERLAP_SIZE         = 16;
    public const int TRUNCATED_MAC_LENGTH = 10;

    private string $buffer;

    private string $sidecar = '';

    public bool $isFinalized = false {
        get {
            return $this->isFinalized;
        }
    }

    public function __construct(
        private readonly string $macKey
    )
    {
        $this->buffer = '';
    }

    public function appendInitializationVector(string $initializationVector): void
    {
        $this->appendSidecarInput($initializationVector);
    }

    public function appendCiphertext(string $ciphertext): void
    {
        $this->appendSidecarInput($ciphertext);
    }

    public function appendMessageAuthenticationCode(string $messageAuthenticationCode): void
    {
        $this->appendSidecarInput($messageAuthenticationCode);
    }

    public function finalize(): void
    {
        if ($this->isFinalized) {
            return;
        }

        if ($this->buffer !== '') {
            $this->sidecar .= $this->createChunkSignature($this->buffer);
            $this->buffer  = '';
        }

        $this->isFinalized = true;
    }

    public function getSidecar(): Sidecar
    {
        if (!$this->isFinalized) {
            throw SidecarNotReadyException::create();
        }

        return new Sidecar($this->sidecar);
    }

    private function appendSidecarInput(string $sidecarInput): void
    {
        if ($this->isFinalized || $sidecarInput === '') {
            return;
        }

        $this->buffer .= $sidecarInput;

        while (strlen($this->buffer) >= self::CHUNK_SIZE + self::OVERLAP_SIZE) {
            $chunk = substr($this->buffer, 0, self::CHUNK_SIZE + self::OVERLAP_SIZE);

            $this->sidecar .= $this->createChunkSignature($chunk);
            $this->buffer  = substr($this->buffer, self::CHUNK_SIZE);
        }
    }

    private function createChunkSignature(string $chunk): string
    {
        return substr(
            hash_hmac('sha256', $chunk, $this->macKey, true),
            0,
            self::TRUNCATED_MAC_LENGTH
        );
    }
}
