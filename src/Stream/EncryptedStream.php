<?php

namespace Illusiard\Psr7Crypt\Stream;

use GuzzleHttp\Psr7\Utils;
use Illusiard\Psr7Crypt\Exception\StreamOperationException;
use Illusiard\Psr7Crypt\Service\SidecarAccumulator;
use Illusiard\Psr7Crypt\Service\StreamingEncryptor;
use Illusiard\Psr7Crypt\ValueObject\ExpandedMediaKey;
use Psr\Http\Message\StreamInterface;
use Throwable;

final class EncryptedStream implements StreamInterface
{
    private string $outputBuffer = '';

    private int $position = 0;

    private bool $isCompleted = false;

    private readonly StreamingEncryptor $streamingEncryptor;

    public function __construct(
        private readonly StreamInterface $stream,
        ExpandedMediaKey                 $expandedMediaKey,
        bool                             $shouldGenerateSidecar = false,
        private readonly int             $sourceReadSize = 8192
    )
    {
        $sidecarAccumulator = null;

        if ($shouldGenerateSidecar) {
            $sidecarAccumulator = new SidecarAccumulator(
                $expandedMediaKey->getMacKey(),
                $expandedMediaKey->getIv()
            );
        }

        $this->streamingEncryptor = new StreamingEncryptor($expandedMediaKey, $sidecarAccumulator);
    }

    public function __toString(): string
    {
        try {
            return $this->getContents();
        } catch (Throwable) {
            return '';
        }
    }

    public function close(): void
    {
        $this->stream->close();
    }

    public function detach()
    {
        return $this->stream->detach();
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

    public function tell(): int
    {
        return $this->position;
    }

    public function eof(): bool
    {
        if ($this->outputBuffer !== '') {
            return false;
        }

        if ($this->isCompleted) {
            return true;
        }

        $this->fillOutputBuffer(1);

        return $this->isCompleted && $this->outputBuffer === '';
    }

    public function isSeekable(): bool
    {
        return false;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        throw new StreamOperationException('EncryptedStream is not seekable.');
    }

    public function rewind(): void
    {
        throw new StreamOperationException('EncryptedStream cannot be rewound.');
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        throw new StreamOperationException('EncryptedStream is read-only.');
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function read(int $length): string
    {
        if ($length < 0) {
            throw new StreamOperationException('Read length cannot be negative.');
        }

        if ($length === 0) {
            return '';
        }

        $this->fillOutputBuffer($length);

        $data               = substr($this->outputBuffer, 0, $length);
        $this->outputBuffer = substr($this->outputBuffer, strlen($data));
        $this->position     += strlen($data);

        return $data;
    }

    public function getContents(): string
    {
        return Utils::copyToString($this);
    }

    public function getMetadata(?string $key = null)
    {
        return $this->stream->getMetadata($key);
    }

    public function getSidecar(): ?string
    {
        return $this->streamingEncryptor->getSidecar();
    }

    private function fillOutputBuffer(int $targetLength): void
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
