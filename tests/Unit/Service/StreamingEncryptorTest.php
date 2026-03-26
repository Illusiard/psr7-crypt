<?php

namespace Illusiard\Psr7Crypt\Tests\Unit\Service;

use Illusiard\Psr7Crypt\Exception\SidecarNotReadyException;
use Illusiard\Psr7Crypt\Service\SidecarAccumulator;
use Illusiard\Psr7Crypt\Service\StreamingEncryptor;
use Illusiard\Psr7Crypt\ValueObject\ExpandedMediaKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class StreamingEncryptorTest extends TestCase
{
    #[DataProvider('plaintextProvider')]
    public function testItEncryptsPlaintextChunksAndAppendsTruncatedMac(string $plaintext): void
    {
        $expandedMediaKey = new ExpandedMediaKey(
            hex2bin(
                '00112233445566778899aabbccddeeff' .
                'ffeeddccbbaa99887766554433221100fedcba98765432100123456789abcdef' .
                '11223344556677889900aabbccddeeffcafebabefeedface0123456789abcdee' .
                '99887766554433221100ffeeddccbbaa1234567890abcdef0fedcba987654321'
            )
        );

        $encryptor = new StreamingEncryptor($expandedMediaKey);
        $originalPlaintext = $plaintext;
        $encrypted = '';

        foreach ([1, 2, 3, 5, 8, 13, 21, 34] as $chunkLength) {
            if ($plaintext === '') {
                break;
            }

            $encrypted .= $encryptor->appendPlaintext(substr($plaintext, 0, $chunkLength));
            $plaintext = substr($plaintext, $chunkLength);
        }

        $encrypted .= $encryptor->appendPlaintext($plaintext);
        $encrypted .= $encryptor->finalize();

        self::assertSame(
            $this->encryptOneShot(
                $expandedMediaKey->getIv(),
                $expandedMediaKey->getCipherKey(),
                $expandedMediaKey->getMacKey(),
                $originalPlaintext
            ),
            $encrypted
        );
    }

    public function testItGeneratesSidecarDuringStreamingEncryption(): void
    {
        $expandedMediaKey = new ExpandedMediaKey(
            hex2bin(
                'c4e6a83a7011cf7824679675d2f10e9e' .
                '8ce388d72275ae064ad1a427840788a0c75a922937c734dbbb7e04c7c64f49af' .
                'eed48c020b22b3050370f0ba58096a342fc64ea290ac45c314718292403d5f05' .
                '55e141f9fec0196767165f402fee5ecbd8265659b0e59733062bc8b2c035efcc'
            )
        );

        $sidecarAccumulator = new SidecarAccumulator(
            $expandedMediaKey->getMacKey(),
            $expandedMediaKey->getIv()
        );
        $encryptor = new StreamingEncryptor($expandedMediaKey, $sidecarAccumulator);
        $plaintext = file_get_contents(__DIR__ . '/../../../task/samples/VIDEO.original');
        $offset = 0;

        foreach ([7, 1024, 33000, 65536, 90000] as $chunkLength) {
            $chunk = substr($plaintext, $offset, $chunkLength);

            if ($chunk === '') {
                break;
            }

            $encryptor->appendPlaintext($chunk);
            $offset += strlen($chunk);
        }

        if ($offset < strlen($plaintext)) {
            $encryptor->appendPlaintext(substr($plaintext, $offset));
        }

        $encryptor->finalize();

        self::assertSame(
            file_get_contents(__DIR__ . '/../../../task/samples/VIDEO.sidecar'),
            $encryptor->getSidecar()
        );
    }

    public function testItFailsWhenSidecarIsRequestedBeforeFinalization(): void
    {
        $expandedMediaKey = new ExpandedMediaKey(random_bytes(ExpandedMediaKey::LENGTH));
        $sidecarAccumulator = new SidecarAccumulator(
            $expandedMediaKey->getMacKey(),
            $expandedMediaKey->getIv()
        );
        $encryptor = new StreamingEncryptor($expandedMediaKey, $sidecarAccumulator);

        $encryptor->appendPlaintext('not-final-yet');

        $this->expectException(SidecarNotReadyException::class);
        $encryptor->getSidecar();
    }

    public static function plaintextProvider(): array
    {
        return [
            'empty' => [''],
            'short' => ['hello'],
            'exact block' => ['1234567890abcdef'],
            'multiple blocks' => ['The quick brown fox jumps over the lazy dog twice.'],
        ];
    }

    private function encryptOneShot(string $iv, string $cipherKey, string $macKey, string $plaintext): string
    {
        $paddingLength = 16 - (strlen($plaintext) % 16);

        if ($paddingLength === 0) {
            $paddingLength = 16;
        }

        $paddedPlaintext = $plaintext . str_repeat(chr($paddingLength), $paddingLength);
        $ciphertext = openssl_encrypt(
            $paddedPlaintext,
            'aes-256-cbc',
            $cipherKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );

        return $ciphertext . substr(hash_hmac('sha256', $iv . $ciphertext, $macKey, true), 0, 10);
    }
}
