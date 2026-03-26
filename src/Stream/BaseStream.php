<?php

namespace Illusiard\Psr7Crypt\Stream;

use Illusiard\Psr7Crypt\Exception\StreamOperationException;
use Psr\Http\Message\StreamInterface;
use Throwable;

abstract class BaseStream implements StreamInterface
{
    protected int    $position     = 0;
    protected string $outputBuffer = '';
    protected bool   $isCompleted  = false;

    protected readonly StreamInterface $stream;

    public function __construct(
        StreamInterface        $stream,
        protected readonly int $sourceReadSize = 8192
    )
    {
        $this->stream = $stream;
    }

    abstract protected function fillOutputBuffer(int $targetLength): void;

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
        throw new StreamOperationException($this->getStreamClassName() . ' is not seekable.');
    }

    public function rewind(): void
    {
        throw new StreamOperationException($this->getStreamClassName() . ' cannot be rewound.');
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        throw new StreamOperationException($this->getStreamClassName() . ' is read-only.');
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

    protected function getStreamClassName(): string
    {
        return basename(str_replace('\\', '/', static::class));
    }
}
