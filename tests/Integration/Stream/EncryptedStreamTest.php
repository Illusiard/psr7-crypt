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
        string    $sampleName,
        MediaType $mediaType,
        ?string   $expectedSidecarHex
    ): void
    {
        $keyExpander      = new KeyExpander();
        $expandedMediaKey = $keyExpander->expand(
            new MediaKey(file_get_contents($this->getSamplePath($sampleName . '.key'))),
            $mediaType
        );

        $plainStream      = Utils::streamFor(fopen($this->getSamplePath($sampleName . '.original'), 'rb'));
        $encryptedStream  = new EncryptedStream($plainStream, $expandedMediaKey, $mediaType->supportsSidecar(), 7777);
        $encryptedPayload = '';

        self::assertSame($mediaType->supportsSidecar(), $encryptedStream->hasSidecar());
        self::assertFalse($encryptedStream->isSidecarReady());

        while (!$encryptedStream->eof()) {
            $encryptedPayload .= $encryptedStream->read(4093);
        }

        self::assertStringEqualsFile(
            $this->getSamplePath($sampleName . '.encrypted'), $encryptedPayload
        );

        if ($expectedSidecarHex !== null) {
            self::assertSame(
                hex2bin($expectedSidecarHex),
                $encryptedStream->getSidecar()?->getValue()
            );
            self::assertTrue($encryptedStream->isSidecarReady());
        } else {
            self::assertNull($encryptedStream->getSidecar());
            self::assertFalse($encryptedStream->isSidecarReady());
        }
    }

    public function testReadByPartsAndEofBehaveCorrectly(): void
    {
        $keyExpander      = new KeyExpander();
        $expandedMediaKey = $keyExpander->expand(
            new MediaKey(file_get_contents($this->getSamplePath('IMAGE.key'))),
            MediaType::Image
        );

        $plainStream     = Utils::streamFor(fopen($this->getSamplePath('IMAGE.original'), 'rb'));
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
        self::assertStringEqualsFile(
            $this->getSamplePath('IMAGE.encrypted'), $result
        );
    }

    public static function sampleProvider(): array
    {
        return [
            'image' => ['IMAGE', MediaType::Image, null],
            'audio' => ['AUDIO', MediaType::Audio, 'eca87e7d15118624dc2e'],
            'video' => ['VIDEO', MediaType::Video, '6466a24d1834fd11975ff59032e27243eb7ffa7af32b12de91dd93903c14fb9335a13a26fbfec938501f04e81292732d0fc181d428d2829b3817d6f453ea3f91e699face1703'],
        ];
    }

    private function getSamplePath(string $fileName): string
    {
        return dirname(__DIR__, 3) . '/task/samples/' . $fileName;
    }
}
