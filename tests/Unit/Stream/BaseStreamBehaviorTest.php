<?php

namespace Illusiard\Psr7Crypt\Tests\Unit\Stream;

use Illusiard\Psr7Crypt\Enum\MediaType;
use Illusiard\Psr7Crypt\Exception\StreamOperationException;
use Illusiard\Psr7Crypt\Service\KeyExpander;
use Illusiard\Psr7Crypt\Stream\DecryptedStream;
use Illusiard\Psr7Crypt\Stream\EncryptedStream;
use Illusiard\Psr7Crypt\ValueObject\ExpandedMediaKey;
use Illusiard\Psr7Crypt\ValueObject\MediaKey;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

final class BaseStreamBehaviorTest extends TestCase
{
    public function testEncryptedStreamOperationMessagesReferenceConcreteClass(): void
    {
        $stream = new EncryptedStream(
            new ScriptedStream(['payload'], true),
            $this->createExpandedMediaKey('IMAGE', MediaType::Image)
        );

        try {
            $stream->seek(0);
            self::fail('Expected StreamOperationException was not thrown.');
        } catch (StreamOperationException $exception) {
            self::assertSame('EncryptedStream is not seekable.', $exception->getMessage());
        }

        try {
            $stream->rewind();
            self::fail('Expected StreamOperationException was not thrown.');
        } catch (StreamOperationException $exception) {
            self::assertSame('EncryptedStream cannot be rewound.', $exception->getMessage());
        }

        try {
            $stream->write('payload');
            self::fail('Expected StreamOperationException was not thrown.');
        } catch (StreamOperationException $exception) {
            self::assertSame('EncryptedStream is read-only.', $exception->getMessage());
        }
    }

    public function testDecryptedStreamOperationMessagesReferenceConcreteClass(): void
    {
        $stream = new DecryptedStream(
            new ScriptedStream(['payload'], true),
            $this->createExpandedMediaKey('IMAGE', MediaType::Image)
        );

        try {
            $stream->seek(0);
            self::fail('Expected StreamOperationException was not thrown.');
        } catch (StreamOperationException $exception) {
            self::assertSame('DecryptedStream is not seekable.', $exception->getMessage());
        }

        try {
            $stream->rewind();
            self::fail('Expected StreamOperationException was not thrown.');
        } catch (StreamOperationException $exception) {
            self::assertSame('DecryptedStream cannot be rewound.', $exception->getMessage());
        }

        try {
            $stream->write('payload');
            self::fail('Expected StreamOperationException was not thrown.');
        } catch (StreamOperationException $exception) {
            self::assertSame('DecryptedStream is read-only.', $exception->getMessage());
        }
    }

    public function testEncryptedStreamRetriesSingleTransientEmptyRead(): void
    {
        $stream = new EncryptedStream(
            new ScriptedStream(['', file_get_contents($this->getSamplePath('IMAGE.original'))], true),
            $this->createExpandedMediaKey('IMAGE', MediaType::Image),
            false,
            8192
        );

        self::assertNotSame('', $stream->read(32));
    }

    public function testDecryptedStreamRetriesSingleTransientEmptyRead(): void
    {
        $stream = new DecryptedStream(
            new ScriptedStream(['', file_get_contents($this->getSamplePath('IMAGE.encrypted'))], true),
            $this->createExpandedMediaKey('IMAGE', MediaType::Image),
            8192
        );

        self::assertNotSame('', $stream->read(32));
    }

    /**
     * @param string $sampleName
     * @param MediaType $mediaType
     * @return ExpandedMediaKey
     */
    private function createExpandedMediaKey(string $sampleName, MediaType $mediaType): ExpandedMediaKey
    {
        return new KeyExpander()->expand(
            new MediaKey(file_get_contents($this->getSamplePath($sampleName . '.key'))),
            $mediaType
        );
    }

    private function getSamplePath(string $fileName): string
    {
        return dirname(__DIR__, 3) . '/task/samples/' . $fileName;
    }
}

final class ScriptedStream implements StreamInterface
{
    private int $position = 0;

    public function __construct(
        private array $chunks,
        private readonly bool $eofAfterChunks
    ) {
    }

    public function __toString(): string
    {
        return '';
    }

    public function close(): void
    {
    }

    public function detach(): null
    {
        return null;
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
        return $this->eofAfterChunks && $this->chunks === [];
    }

    public function isSeekable(): bool
    {
        return false;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        throw new StreamOperationException('ScriptedStream is not seekable.');
    }

    public function rewind(): void
    {
        throw new StreamOperationException('ScriptedStream cannot be rewound.');
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function write(string $string): int
    {
        throw new StreamOperationException('ScriptedStream is read-only.');
    }

    public function isReadable(): bool
    {
        return true;
    }

    public function read(int $length): string
    {
        if ($this->chunks === []) {
            return '';
        }

        $chunk = array_shift($this->chunks);
        $this->position += strlen($chunk);

        return $chunk;
    }

    public function getContents(): string
    {
        return '';
    }

    public function getMetadata(?string $key = null): null
    {
        return null;
    }
}
