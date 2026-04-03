<?php

namespace Illusiard\Psr7Crypt\Service;

use HashContext;
use Illusiard\Psr7Crypt\Exception\SidecarNotReadyException;
use Illusiard\Psr7Crypt\ValueObject\Sidecar;

final class SidecarAccumulator
{
    public const int CHUNK_SIZE           = 65536;
    public const int OVERLAP_SIZE         = 16;
    public const int TRUNCATED_MAC_LENGTH = 10;

    private HashContext $chunkContext;

    private int $chunkBytesHashed = 0;

    private string $nextChunkPrefix = '';

    private string $sidecar = '';

    public bool $isFinalized
        = false {
            get {
                return $this->isFinalized;
            }
        }

    public function __construct(
        private readonly string $macKey
    )
    {
        $this->chunkContext = $this->createChunkContext();
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

        if ($this->chunkBytesHashed > 0) {
            $this->sidecar .= $this->finalizeCurrentChunk();
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

        while ($sidecarInput !== '') {
            $remainingBytes = self::CHUNK_SIZE + self::OVERLAP_SIZE - $this->chunkBytesHashed;
            $chunkPart      = substr($sidecarInput, 0, $remainingBytes);
            $partLength     = strlen($chunkPart);

            hash_update($this->chunkContext, $chunkPart);
            $this->captureNextChunkPrefix($chunkPart);

            $this->chunkBytesHashed += $partLength;
            $sidecarInput           = substr($sidecarInput, $partLength);

            if ($this->chunkBytesHashed === self::CHUNK_SIZE + self::OVERLAP_SIZE) {
                $this->sidecar .= $this->finalizeCurrentChunk();
                $this->startNextChunk();
            }
        }
    }

    private function createChunkContext(): HashContext
    {
        return hash_init('sha256', HASH_HMAC, $this->macKey);
    }

    private function captureNextChunkPrefix(string $chunkPart): void
    {
        $prefixStartOffset = max(0, self::CHUNK_SIZE - $this->chunkBytesHashed);
        $prefixEndOffset   = min(
            strlen($chunkPart),
            self::CHUNK_SIZE + self::OVERLAP_SIZE - $this->chunkBytesHashed
        );

        if ($prefixStartOffset >= $prefixEndOffset) {
            return;
        }

        $this->nextChunkPrefix .= substr($chunkPart, $prefixStartOffset, $prefixEndOffset - $prefixStartOffset);
    }

    private function finalizeCurrentChunk(): string
    {
        return substr(
            hash_final($this->chunkContext, true),
            0,
            self::TRUNCATED_MAC_LENGTH
        );
    }

    private function startNextChunk(): void
    {
        $this->chunkContext     = $this->createChunkContext();
        $this->chunkBytesHashed = strlen($this->nextChunkPrefix);

        if ($this->nextChunkPrefix !== '') {
            hash_update($this->chunkContext, $this->nextChunkPrefix);
        }

        $this->nextChunkPrefix = '';
    }
}
