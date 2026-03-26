<?php

namespace Illusiard\Psr7Crypt\Tests\Samples;

use GuzzleHttp\Psr7\Utils;
use Illusiard\Psr7Crypt\Enum\MediaType;
use Illusiard\Psr7Crypt\Exception\InvalidMacException;
use Illusiard\Psr7Crypt\Service\KeyExpander;
use Illusiard\Psr7Crypt\Stream\DecryptedStream;
use Illusiard\Psr7Crypt\Stream\EncryptedStream;
use Illusiard\Psr7Crypt\ValueObject\ExpandedMediaKey;
use Illusiard\Psr7Crypt\ValueObject\MediaKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SampleStreamsTest extends TestCase
{
    #[DataProvider('sampleProvider')]
    public function testSampleKeysAreStoredAsRawBinary(string $sampleName): void
    {
        $key = file_get_contents($this->getSamplePath($sampleName, 'key'));

        self::assertSame(32, strlen($key));
        self::assertFalse((bool) base64_decode($key, true));
        self::assertFalse(ctype_xdigit(trim($key)));
    }

    #[DataProvider('sampleProvider')]
    public function testItDecryptsSampleEncryptedPayloadWithFullRead(
        string $sampleName,
        MediaType $mediaType
    ): void {
        $decryptedStream = new DecryptedStream(
            Utils::streamFor(fopen($this->getSamplePath($sampleName, 'encrypted'), 'rb')),
            $this->createExpandedMediaKey($sampleName, $mediaType),
            4097
        );

        self::assertStringEqualsFile(
            $this->getSamplePath($sampleName, 'original'), $decryptedStream->getContents()
        );
    }

    #[DataProvider('sampleProvider')]
    public function testItDecryptsSampleEncryptedPayloadWithPartialReads(
        string $sampleName,
        MediaType $mediaType
    ): void {
        $decryptedStream = new DecryptedStream(
            Utils::streamFor(fopen($this->getSamplePath($sampleName, 'encrypted'), 'rb')),
            $this->createExpandedMediaKey($sampleName, $mediaType),
            997
        );

        self::assertStringEqualsFile(
            $this->getSamplePath($sampleName, 'original'), $this->readStreamInChunks($decryptedStream, [1, 7, 13, 64, 1024])
        );
    }

    #[DataProvider('sampleProvider')]
    public function testItEncryptsSampleOriginalPayloadWithFullRead(
        string $sampleName,
        MediaType $mediaType
    ): void {
        $encryptedStream = new EncryptedStream(
            Utils::streamFor(fopen($this->getSamplePath($sampleName, 'original'), 'rb')),
            $this->createExpandedMediaKey($sampleName, $mediaType),
            $this->sampleHasSidecarFixture($sampleName),
            7777
        );

        self::assertStringEqualsFile(
            $this->getSamplePath($sampleName, 'encrypted'), $encryptedStream->getContents()
        );
    }

    #[DataProvider('sampleProvider')]
    public function testItEncryptsSampleOriginalPayloadWithPartialReads(
        string $sampleName,
        MediaType $mediaType
    ): void {
        $encryptedStream = new EncryptedStream(
            Utils::streamFor(fopen($this->getSamplePath($sampleName, 'original'), 'rb')),
            $this->createExpandedMediaKey($sampleName, $mediaType),
            $this->sampleHasSidecarFixture($sampleName),
            1024
        );

        self::assertStringEqualsFile(
            $this->getSamplePath($sampleName, 'encrypted'), $this->readStreamInChunks($encryptedStream, [1, 7, 13, 64, 1024])
        );
    }

    #[DataProvider('sampleWithSidecarProvider')]
    public function testItMatchesSampleSidecar(
        string $sampleName,
        MediaType $mediaType
    ): void {
        $encryptedStream = new EncryptedStream(
            Utils::streamFor(fopen($this->getSamplePath($sampleName, 'original'), 'rb')),
            $this->createExpandedMediaKey($sampleName, $mediaType),
            true,
            2048
        );

        $this->readStreamInChunks($encryptedStream, [1, 7, 13, 64, 1024]);

        self::assertTrue($encryptedStream->hasSidecar());
        self::assertTrue($encryptedStream->isSidecarReady());
        self::assertStringEqualsFile(
            $this->getSamplePath($sampleName, 'sidecar'), $encryptedStream->getSidecar()?->getValue()
        );
    }

    #[DataProvider('sampleProvider')]
    public function testItRejectsSampleEncryptedPayloadWhenCiphertextByteIsTampered(
        string $sampleName,
        MediaType $mediaType
    ): void {
        $encryptedPayload = file_get_contents($this->getSamplePath($sampleName, 'encrypted'));
        $tamperedPayload = $encryptedPayload;
        $tamperedPayload[0] = $tamperedPayload[0] ^ "\xff";

        $decryptedStream = new DecryptedStream(
            Utils::streamFor($tamperedPayload),
            $this->createExpandedMediaKey($sampleName, $mediaType),
            1024
        );

        $this->expectException(InvalidMacException::class);
        $decryptedStream->getContents();
    }

    #[DataProvider('sampleProvider')]
    public function testItRejectsSampleEncryptedPayloadWhenMacByteIsTampered(
        string $sampleName,
        MediaType $mediaType
    ): void {
        $encryptedPayload = file_get_contents($this->getSamplePath($sampleName, 'encrypted'));
        $tamperedPayload = substr($encryptedPayload, 0, -1) . ($encryptedPayload[-1] ^ "\xff");

        $decryptedStream = new DecryptedStream(
            Utils::streamFor($tamperedPayload),
            $this->createExpandedMediaKey($sampleName, $mediaType),
            1024
        );

        $this->expectException(InvalidMacException::class);
        $decryptedStream->getContents();
    }

    public static function sampleProvider(): array
    {
        return [
            'image' => ['IMAGE', MediaType::Image],
            'audio' => ['AUDIO', MediaType::Audio],
            'video' => ['VIDEO', MediaType::Video],
        ];
    }

    public static function sampleWithSidecarProvider(): array
    {
        return [
            'video' => ['VIDEO', MediaType::Video],
        ];
    }

    /**
     * @param string $sampleName
     * @param MediaType $mediaType
     * @return ExpandedMediaKey
     */
    private function createExpandedMediaKey(string $sampleName, MediaType $mediaType): ExpandedMediaKey
    {
        return new KeyExpander()->expand(
            new MediaKey(file_get_contents($this->getSamplePath($sampleName, 'key'))),
            $mediaType
        );
    }

    private function readStreamInChunks($stream, array $chunkLengths): string
    {
        $contents = '';

        while (!$stream->eof()) {
            foreach ($chunkLengths as $chunkLength) {
                if ($stream->eof()) {
                    break;
                }

                $contents .= $stream->read($chunkLength);
            }
        }

        return $contents;
    }

    private function sampleHasSidecarFixture(string $sampleName): bool
    {
        return is_file($this->getSamplePath($sampleName, 'sidecar'));
    }

    private function getSamplePath(string $sampleName, string $extension): string
    {
        return dirname(__DIR__, 2) . '/task/samples/' . $sampleName . '.' . $extension;
    }
}
