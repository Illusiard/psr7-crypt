<?php

namespace Illusiard\Psr7Crypt\Stream;

use Illusiard\Psr7Crypt\Exception\StreamOperationException;
use Illusiard\Psr7Crypt\Service\StreamingDecryptor;
use Illusiard\Psr7Crypt\ValueObject\ExpandedMediaKey;
use Psr\Http\Message\StreamInterface;
use Throwable;

final class DecryptedStream extends BaseStream
{
    private readonly StreamingDecryptor $streamingDecryptor;

    public function __construct(
        StreamInterface $stream,
        ExpandedMediaKey $expandedMediaKey,
        int $sourceReadSize = 8192
    )
    {
        parent::__construct($stream, $expandedMediaKey, $sourceReadSize);

        $this->streamingDecryptor = new StreamingDecryptor($expandedMediaKey);
    }

    public function getSize(): ?int
    {
        return null;
    }

    public function getContents(): string
    {
        $contents = '';

        while (!$this->eof()) {
            $contents .= $this->read(8192);
        }

        return $contents;
    }

    public function getMetadata(?string $key = null)
    {
        return $this->stream->getMetadata($key);
    }

    protected function fillOutputBuffer(int $targetLength): void
    {
        while (strlen($this->outputBuffer) < $targetLength && !$this->isCompleted) {
            $encryptedChunk = $this->stream->read($this->sourceReadSize);

            if ($encryptedChunk !== '') {
                $this->outputBuffer .= $this->streamingDecryptor->appendEncryptedData($encryptedChunk);
                continue;
            }

            if ($this->stream->eof()) {
                $this->outputBuffer .= $this->streamingDecryptor->finalize();
                $this->isCompleted  = true;
            }

            break;
        }
    }
}
