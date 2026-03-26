<?php

namespace Illusiard\Psr7Crypt\Tests\Unit\Enum;

use Illusiard\Psr7Crypt\Enum\MediaType;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class MediaTypeTest extends TestCase
{
    #[DataProvider('mediaTypeProvider')]
    public function testItKnowsWhetherMediaTypeSupportsSidecar(MediaType $mediaType, bool $expectedValue): void
    {
        self::assertSame($expectedValue, $mediaType->supportsSidecar());
    }

    public static function mediaTypeProvider(): array
    {
        return [
            'image'    => [MediaType::Image, false],
            'video'    => [MediaType::Video, true],
            'audio'    => [MediaType::Audio, true],
            'document' => [MediaType::Document, false],
        ];
    }
}
