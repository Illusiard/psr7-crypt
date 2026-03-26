<?php

namespace Illusiard\Psr7Crypt\Tests\Integration\Stream;

use GuzzleHttp\Psr7\Utils;
use Illusiard\Psr7Crypt\Enum\MediaType;
use Illusiard\Psr7Crypt\Exception\InvalidMacException;
use Illusiard\Psr7Crypt\Service\KeyExpander;
use Illusiard\Psr7Crypt\Stream\DecryptedStream;
use Illusiard\Psr7Crypt\Stream\EncryptedStream;
use Illusiard\Psr7Crypt\ValueObject\MediaKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class DecryptedStreamTest extends TestCase
{
    #[DataProvider('sampleProvider')]
    public function testItMatchesProvidedOriginalSamples(string $sampleName, MediaType $mediaType): void
    {
        $keyExpander      = new KeyExpander();
        $expandedMediaKey = $keyExpander->expand(
            new MediaKey(file_get_contents($this->getSamplePath($sampleName . '.key'))),
            $mediaType
        );

        $encryptedStream = Utils::streamFor(fopen($this->getSamplePath($sampleName . '.encrypted'), 'rb'));
        $decryptedStream = new DecryptedStream($encryptedStream, $expandedMediaKey, 4097);

        $plaintext = '';

        while (!$decryptedStream->eof()) {
            $plaintext .= $decryptedStream->read(777);
        }

        self::assertStringEqualsFile($this->getSamplePath($sampleName . '.original'), $plaintext);
    }

    public function testEncryptThenDecryptRoundTripWorksThroughStreams(): void
    {
        $keyExpander      = new KeyExpander();
        $expandedMediaKey = $keyExpander->expand(
            new MediaKey(file_get_contents($this->getSamplePath('VIDEO.key'))),
            MediaType::Video
        );

        $plaintext       = file_get_contents($this->getSamplePath('VIDEO.original'));
        $plainStream     = Utils::streamFor($plaintext);
        $encryptedStream = new EncryptedStream($plainStream, $expandedMediaKey, true, 3001);
        $decryptedStream = new DecryptedStream($encryptedStream, $expandedMediaKey, 5003);

        self::assertSame($plaintext, $decryptedStream->getContents());
    }

    public function testItThrowsInvalidMacExceptionForTamperedPayload(): void
    {
        $keyExpander      = new KeyExpander();
        $expandedMediaKey = $keyExpander->expand(
            new MediaKey(file_get_contents($this->getSamplePath('IMAGE.key'))),
            MediaType::Image
        );

        $encryptedPayload = file_get_contents($this->getSamplePath('IMAGE.encrypted'));
        $tamperedPayload  = substr($encryptedPayload, 0, -1) . ($encryptedPayload[-1] ^ "\xff");
        $encryptedStream  = Utils::streamFor($tamperedPayload);
        $decryptedStream  = new DecryptedStream($encryptedStream, $expandedMediaKey, 1024);

        $this->expectException(InvalidMacException::class);
        $decryptedStream->read(1);
    }

    public function testReadByPartsAndEofBehaveCorrectly(): void
    {
        $keyExpander      = new KeyExpander();
        $expandedMediaKey = $keyExpander->expand(
            new MediaKey(file_get_contents($this->getSamplePath('AUDIO.key'))),
            MediaType::Audio
        );

        $encryptedStream = Utils::streamFor(fopen($this->getSamplePath('AUDIO.encrypted'), 'rb'));
        $decryptedStream = new DecryptedStream($encryptedStream, $expandedMediaKey, 997);

        self::assertFalse($decryptedStream->eof());

        $plaintext = '';

        foreach ([1, 2, 7, 64, 257, 1024, 4096] as $length) {
            $chunk = $decryptedStream->read($length);

            if ($chunk === '') {
                break;
            }

            $plaintext .= $chunk;
            self::assertSame(strlen($plaintext), $decryptedStream->tell());
        }

        while (!$decryptedStream->eof()) {
            $plaintext .= $decryptedStream->read(2048);
        }

        self::assertTrue($decryptedStream->eof());
        self::assertStringEqualsFile($this->getSamplePath('AUDIO.original'), $plaintext);
    }

    public static function sampleProvider(): array
    {
        return [
            'image' => ['IMAGE', MediaType::Image],
            'audio' => ['AUDIO', MediaType::Audio],
            'video' => ['VIDEO', MediaType::Video],
        ];
    }

    private function getSamplePath(string $fileName): string
    {
        return dirname(__DIR__, 3) . '/task/samples/' . $fileName;
    }
}
