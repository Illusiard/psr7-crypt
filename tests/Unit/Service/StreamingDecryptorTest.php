<?php

namespace Illusiard\Psr7Crypt\Tests\Unit\Service;

use Illusiard\Psr7Crypt\Exception\InvalidEncryptedPayloadException;
use Illusiard\Psr7Crypt\Exception\InvalidMacException;
use Illusiard\Psr7Crypt\Service\StreamingDecryptor;
use Illusiard\Psr7Crypt\Service\StreamingEncryptor;
use Illusiard\Psr7Crypt\ValueObject\ExpandedMediaKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Random\RandomException;

final class StreamingDecryptorTest extends TestCase
{
    #[DataProvider('plaintextProvider')]
    public function testEncryptThenDecryptReturnsOriginalPlaintext(string $plaintext): void
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
        $encryptedPayload = $encryptor->appendPlaintext($plaintext) . $encryptor->finalize();

        $decryptor = new StreamingDecryptor($expandedMediaKey);
        $decryptedPayload = '';
        $offset = 0;

        foreach ([1, 2, 5, 8, 13, 21, 34] as $chunkLength) {
            $chunk = substr($encryptedPayload, $offset, $chunkLength);

            if ($chunk === '') {
                break;
            }

            $decryptedPayload .= $decryptor->appendEncryptedData($chunk);
            $offset += strlen($chunk);
        }

        if ($offset < strlen($encryptedPayload)) {
            $decryptedPayload .= $decryptor->appendEncryptedData(substr($encryptedPayload, $offset));
        }

        $decryptedPayload .= $decryptor->finalize();

        self::assertSame($plaintext, $decryptedPayload);
    }

    /**
     * @return void
     * @throws RandomException
     */
    public function testItRejectsInvalidMac(): void
    {
        $expandedMediaKey = new ExpandedMediaKey(random_bytes(ExpandedMediaKey::LENGTH));
        $encryptor = new StreamingEncryptor($expandedMediaKey);
        $encryptedPayload = $encryptor->appendPlaintext('payload') . $encryptor->finalize();
        $tamperedPayload = substr($encryptedPayload, 0, -1) . ($encryptedPayload[-1] ^ "\xff");

        $decryptor = new StreamingDecryptor($expandedMediaKey);
        $decryptor->appendEncryptedData($tamperedPayload);

        $this->expectException(InvalidMacException::class);
        $decryptor->finalize();
    }

    /**
     * @return void
     * @throws RandomException
     */
    public function testItRejectsTooShortEncryptedPayload(): void
    {
        $decryptor = new StreamingDecryptor(new ExpandedMediaKey(random_bytes(ExpandedMediaKey::LENGTH)));
        $decryptor->appendEncryptedData('short');

        $this->expectException(InvalidEncryptedPayloadException::class);
        $decryptor->finalize();
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
}
