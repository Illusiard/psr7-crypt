<?php

namespace Illusiard\Psr7Crypt\Service;

use Illusiard\Psr7Crypt\Exception\SidecarNotReadyException;

final class SidecarAccumulator
{
    public const int CHUNK_SIZE       = 65536;
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
        private readonly string $macKey,
        string                  $initialData = ''
    )
    {
        $this->buffer = $initialData;
    }

    public function appendCiphertext(string $ciphertext): void
    {
        if ($this->isFinalized || $ciphertext === '') {
            return;
        }

        $this->buffer .= $ciphertext;

        while (strlen($this->buffer) >= self::CHUNK_SIZE + self::OVERLAP_SIZE) {
            $chunk = substr($this->buffer, 0, self::CHUNK_SIZE + self::OVERLAP_SIZE);

            $this->sidecar .= $this->createChunkSignature($chunk);
            $this->buffer  = substr($this->buffer, self::CHUNK_SIZE);
        }
    }

    public function finalize(string $trailingData = ''): void
    {
        if ($this->isFinalized) {
            return;
        }

        if ($trailingData !== '') {
            $this->buffer .= $trailingData;
        }

        if ($this->buffer !== '') {
            $this->sidecar .= $this->createChunkSignature($this->buffer);
            $this->buffer  = '';
        }

        $this->isFinalized = true;
    }

    public function getSidecar(): string
    {
        if (!$this->isFinalized) {
            throw SidecarNotReadyException::create();
        }

        return $this->sidecar;
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
