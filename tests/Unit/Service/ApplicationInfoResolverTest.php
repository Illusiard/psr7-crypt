<?php

namespace Illusiard\Psr7Crypt\Tests\Unit\Service;

use Illusiard\Psr7Crypt\Enum\MediaType;
use Illusiard\Psr7Crypt\Service\ApplicationInfoResolver;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ApplicationInfoResolverTest extends TestCase
{
    #[DataProvider('mediaTypeProvider')]
    public function testItResolvesExpectedApplicationInfo(MediaType $mediaType, string $expectedApplicationInfo): void
    {
        $resolver = new ApplicationInfoResolver();

        self::assertSame($expectedApplicationInfo, $resolver->getApplicationInfo($mediaType));
    }

    public static function mediaTypeProvider(): array
    {
        return [
            'image'    => [MediaType::Image, 'WhatsApp Image Keys'],
            'video'    => [MediaType::Video, 'WhatsApp Video Keys'],
            'audio'    => [MediaType::Audio, 'WhatsApp Audio Keys'],
            'document' => [MediaType::Document, 'WhatsApp Document Keys'],
        ];
    }
}
