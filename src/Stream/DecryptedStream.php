<?php

namespace Illusiard\Psr7Crypt\Stream;

use GuzzleHttp\Psr7\Utils;
use Illusiard\Psr7Crypt\Exception\StreamOperationException;
use Illusiard\Psr7Crypt\Service\StreamingDecryptor;
use Illusiard\Psr7Crypt\ValueObject\ExpandedMediaKey;
use Psr\Http\Message\StreamInterface;
use Throwable;

final class DecryptedStream implements StreamInterface
{
    private int $position = 0;

    private bool $isInitialized = false;

    private readonly StreamingDecryptor $streamingDecryptor;

    private readonly StreamInterface $outputStream;

    public function __construct(
        private readonly StreamInterface $stream,
        ExpandedMediaKey $expandedMediaKey,
        private readonly int $sourceReadSize = 8192
    ) {
        $this->streamingDecryptor = new StreamingDecryptor($expandedMediaKey);
        $this->outputStream = Utils::streamFor(fopen('php://temp', 'r+'));
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
        $this->outputStream->close();
        $this->stream->close();
    }

    public function detach()
    {
        return $this->outputStream->detach();
    }

    public function getSize(): ?int
    {
        return null;
    }

    public function tell(): int
    {
        return $this->position;
    }

    public function eof(): bool
    {
        $this->initializeOutputStream();

        return $this->outputStream->eof();
    }

    public function isSeekable(): bool
    {
        return false;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        throw new StreamOperationException('DecryptedStream is not seekable.');
    }

    public function rewind(): void
    {
        throw new StreamOperationException('DecryptedStream cannot be rewound.');
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        throw new StreamOperationException('DecryptedStream is read-only.');
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

        $this->initializeOutputStream();

        $data = $this->outputStream->read($length);
        $this->position += strlen($data);

        return $data;
    }

    public function getContents(): string
    {
        $this->initializeOutputStream();

        return Utils::copyToString($this);
    }

    public function getMetadata(?string $key = null)
    {
        return $this->stream->getMetadata($key);
    }

    private function initializeOutputStream(): void
    {
        if ($this->isInitialized) {
            return;
        }

        while (!$this->stream->eof()) {
            $encryptedChunk = $this->stream->read($this->sourceReadSize);

            if ($encryptedChunk === '') {
                continue;
            }

            $decryptedChunk = $this->streamingDecryptor->appendEncryptedData($encryptedChunk);

            if ($decryptedChunk !== '') {
                $this->outputStream->write($decryptedChunk);
            }
        }

        $finalChunk = $this->streamingDecryptor->finalize();

        if ($finalChunk !== '') {
            $this->outputStream->write($finalChunk);
        }

        $this->outputStream->rewind();
        $this->isInitialized = true;
    }
}
