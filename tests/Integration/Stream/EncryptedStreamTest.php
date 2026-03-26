<?php

namespace Illusiard\Psr7Crypt\Tests\Integration\Stream;

use GuzzleHttp\Psr7\Utils;
use Illusiard\Psr7Crypt\Enum\MediaType;
use Illusiard\Psr7Crypt\Service\KeyExpander;
use Illusiard\Psr7Crypt\Stream\EncryptedStream;
use Illusiard\Psr7Crypt\ValueObject\MediaKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class EncryptedStreamTest extends TestCase
{
    #[DataProvider('sampleProvider')]
    public function testItMatchesProvidedEncryptedSamples(
        string $sampleName,
        MediaType $mediaType,
        bool $shouldGenerateSidecar
    ): void {
        $keyExpander = new KeyExpander();
        $expandedMediaKey = $keyExpander->expand(
            new MediaKey(file_get_contents($this->getSamplePath($sampleName . '.key'))),
            $mediaType
        );

        $plainStream = Utils::streamFor(fopen($this->getSamplePath($sampleName . '.original'), 'rb'));
        $encryptedStream = new EncryptedStream($plainStream, $expandedMediaKey, $shouldGenerateSidecar, 7777);
        $encryptedPayload = '';

        while (!$encryptedStream->eof()) {
            $encryptedPayload .= $encryptedStream->read(4093);
        }

        self::assertSame(
            file_get_contents($this->getSamplePath($sampleName . '.encrypted')),
            $encryptedPayload
        );

        if ($shouldGenerateSidecar) {
            self::assertSame(
                file_get_contents($this->getSamplePath($sampleName . '.sidecar')),
                $encryptedStream->getSidecar()
            );
        } else {
            self::assertNull($encryptedStream->getSidecar());
        }
    }

    public function testReadByPartsAndEofBehaveCorrectly(): void
    {
        $keyExpander = new KeyExpander();
        $expandedMediaKey = $keyExpander->expand(
            new MediaKey(file_get_contents($this->getSamplePath('IMAGE.key'))),
            MediaType::Image
        );

        $plainStream = Utils::streamFor(fopen($this->getSamplePath('IMAGE.original'), 'rb'));
        $encryptedStream = new EncryptedStream($plainStream, $expandedMediaKey, false, 1024);

        self::assertFalse($encryptedStream->eof());

        $result = '';

        foreach ([1, 2, 7, 64, 513, 8192, 16384, 32768] as $length) {
            $chunk = $encryptedStream->read($length);

            if ($chunk === '') {
                break;
            }

            $result .= $chunk;
            self::assertSame(strlen($result), $encryptedStream->tell());
        }

        while (!$encryptedStream->eof()) {
            $result .= $encryptedStream->read(5000);
        }

        self::assertTrue($encryptedStream->eof());
        self::assertSame(
            file_get_contents($this->getSamplePath('IMAGE.encrypted')),
            $result
        );
    }

    public static function sampleProvider(): array
    {
        return [
            'image' => ['IMAGE', MediaType::Image, false],
            'audio' => ['AUDIO', MediaType::Audio, false],
            'video' => ['VIDEO', MediaType::Video, true],
        ];
    }

    private function getSamplePath(string $fileName): string
    {
        return dirname(__DIR__, 3) . '/task/samples/' . $fileName;
    }
}
