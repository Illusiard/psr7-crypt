<?php

namespace Illusiard\Psr7Crypt\Stream;

use GuzzleHttp\Psr7\Utils;
use Illusiard\Psr7Crypt\Exception\StreamOperationException;
use Illusiard\Psr7Crypt\Service\SidecarAccumulator;
use Illusiard\Psr7Crypt\Service\StreamingEncryptor;
use Illusiard\Psr7Crypt\ValueObject\ExpandedMediaKey;
use Illusiard\Psr7Crypt\ValueObject\Sidecar;
use Psr\Http\Message\StreamInterface;

final class EncryptedStream extends BaseStream
{
    private readonly StreamingEncryptor $streamingEncryptor;

    public function __construct(
        StreamInterface  $stream,
        ExpandedMediaKey $expandedMediaKey,
        bool             $shouldGenerateSidecar = false,
        int              $sourceReadSize = 8192
    )
    {
        parent::__construct($stream, $expandedMediaKey, $sourceReadSize);

        $sidecarAccumulator = null;

        if ($shouldGenerateSidecar) {
            $sidecarAccumulator = new SidecarAccumulator(
                $expandedMediaKey->getMacKey(),
                $expandedMediaKey->getIv()
            );
        }

        $this->streamingEncryptor = new StreamingEncryptor($expandedMediaKey, $sidecarAccumulator);
    }

    public function getSize(): ?int
    {
        $sourceSize = $this->stream->getSize();

        if ($sourceSize === null) {
            return null;
        }

        $paddingLength = StreamingEncryptor::BLOCK_SIZE - ($sourceSize % StreamingEncryptor::BLOCK_SIZE);

        if ($paddingLength === 0) {
            $paddingLength = StreamingEncryptor::BLOCK_SIZE;
        }

        return $sourceSize + $paddingLength + StreamingEncryptor::TRUNCATED_MAC_LENGTH;
    }

    public function getContents(): string
    {
        return Utils::copyToString($this);
    }

    public function getMetadata(?string $key = null)
    {
        return $this->stream->getMetadata($key);
    }

    public function hasSidecar(): bool
    {
        return $this->streamingEncryptor->hasSidecar();
    }

    public function isSidecarReady(): bool
    {
        return $this->streamingEncryptor->isSidecarReady();
    }

    public function getSidecar(): ?Sidecar
    {
        return $this->streamingEncryptor->getSidecar();
    }

    protected function fillOutputBuffer(int $targetLength): void
    {
        while (strlen($this->outputBuffer) < $targetLength && !$this->isCompleted) {
            $plaintext = $this->stream->read($this->sourceReadSize);

            if ($plaintext !== '') {
                $this->outputBuffer .= $this->streamingEncryptor->appendPlaintext($plaintext);
                continue;
            }

            if ($this->stream->eof()) {
                $this->outputBuffer .= $this->streamingEncryptor->finalize();
                $this->isCompleted  = true;
            }

            break;
        }
    }
}
