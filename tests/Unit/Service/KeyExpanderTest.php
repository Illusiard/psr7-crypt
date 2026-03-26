<?php

namespace Illusiard\Psr7Crypt\Tests\Unit\Service;

use Illusiard\Psr7Crypt\Enum\MediaType;
use Illusiard\Psr7Crypt\Service\KeyExpander;
use Illusiard\Psr7Crypt\ValueObject\ExpandedMediaKey;
use Illusiard\Psr7Crypt\ValueObject\MediaKey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Random\RandomException;

final class KeyExpanderTest extends TestCase
{
    #[DataProvider('sampleKeyExpansionProvider')]
    public function testItExpandsMediaKeyUsingSampleVectors(
        MediaType $mediaType,
        string    $mediaKeyHex,
        string    $expectedExpandedKeyHex,
        string    $expectedIvHex,
        string    $expectedCipherKeyHex,
        string    $expectedMacKeyHex,
        string    $expectedRefKeyHex
    ): void
    {
        $keyExpander = new KeyExpander();

        $expandedMediaKey = $keyExpander->expand(
            new MediaKey(hex2bin($mediaKeyHex)),
            $mediaType
        );

        self::assertSame($expectedExpandedKeyHex, bin2hex($expandedMediaKey->getValue()));
        self::assertSame($expectedIvHex, bin2hex($expandedMediaKey->getIv()));
        self::assertSame($expectedCipherKeyHex, bin2hex($expandedMediaKey->getCipherKey()));
        self::assertSame($expectedMacKeyHex, bin2hex($expandedMediaKey->getMacKey()));
        self::assertSame($expectedRefKeyHex, bin2hex($expandedMediaKey->getRefKey()));
    }

    /**
     * @return void
     * @throws RandomException
     */
    public function testExpandedMediaKeySegmentsHaveExpectedLengths(): void
    {
        $expandedMediaKey = new ExpandedMediaKey(random_bytes(ExpandedMediaKey::LENGTH));

        self::assertSame(ExpandedMediaKey::LENGTH, strlen($expandedMediaKey->getValue()));
        self::assertSame(ExpandedMediaKey::IV_LENGTH, strlen($expandedMediaKey->getIv()));
        self::assertSame(ExpandedMediaKey::CIPHER_KEY_LENGTH, strlen($expandedMediaKey->getCipherKey()));
        self::assertSame(ExpandedMediaKey::MAC_KEY_LENGTH, strlen($expandedMediaKey->getMacKey()));
        self::assertSame(ExpandedMediaKey::REF_KEY_LENGTH, strlen($expandedMediaKey->getRefKey()));
    }

    public static function sampleKeyExpansionProvider(): array
    {
        return [
            'image sample' => [
                MediaType::Image,
                '958add391347d742b641549f053259d853474c8e0420f1d1ef934d47080930a6',
                '4309b90f8022180fac636d7890c09ffd4f903101cb6a18e20307f1d0bf4b4921f94def28301c2c67e3e716d69dfdb5934782add755fe6b209951d1b6628946fa1d93b84a18e5bda6247aba62112beb96fd1293c263586c9f414119de6f28c31ada05d0fbb02aae28284ffc35efd9e3c7',
                '4309b90f8022180fac636d7890c09ffd',
                '4f903101cb6a18e20307f1d0bf4b4921f94def28301c2c67e3e716d69dfdb593',
                '4782add755fe6b209951d1b6628946fa1d93b84a18e5bda6247aba62112beb96',
                'fd1293c263586c9f414119de6f28c31ada05d0fbb02aae28284ffc35efd9e3c7',
            ],
            'audio sample' => [
                MediaType::Audio,
                '519a9f22f17059c8d6126cdfc27c300f668d84a549cdea7e43e16d7b36e0f2ab',
                'c691a38c10052fa2a2e7ed2f823c8070c8a14ec8f172540ebf89b72d8e8be39f1213648e5dfad6b63c0abe792dcc7a0166496f5f07da19fd6e80eb6b32f5c5171739a6a53fad2646c748fa7b5fa9999eed1bb3c2809c15ad317892b7cf173696031abc439a416b40ffbce4b82d442875',
                'c691a38c10052fa2a2e7ed2f823c8070',
                'c8a14ec8f172540ebf89b72d8e8be39f1213648e5dfad6b63c0abe792dcc7a01',
                '66496f5f07da19fd6e80eb6b32f5c5171739a6a53fad2646c748fa7b5fa9999e',
                'ed1bb3c2809c15ad317892b7cf173696031abc439a416b40ffbce4b82d442875',
            ],
            'video sample' => [
                MediaType::Video,
                'd2299c8dd8cf224de008abc265eb17b1ea69bcdd10245d4abad111d72f7615b6',
                'c4e6a83a7011cf7824679675d2f10e9e8ce388d72275ae064ad1a427840788a0c75a922937c734dbbb7e04c7c64f49afeed48c020b22b3050370f0ba58096a342fc64ea290ac45c314718292403d5f0555e141f9fec0196767165f402fee5ecbd8265659b0e59733062bc8b2c035efcc',
                'c4e6a83a7011cf7824679675d2f10e9e',
                '8ce388d72275ae064ad1a427840788a0c75a922937c734dbbb7e04c7c64f49af',
                'eed48c020b22b3050370f0ba58096a342fc64ea290ac45c314718292403d5f05',
                '55e141f9fec0196767165f402fee5ecbd8265659b0e59733062bc8b2c035efcc',
            ],
        ];
    }
}
