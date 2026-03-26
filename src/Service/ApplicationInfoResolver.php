<?php

namespace Illusiard\Psr7Crypt\Service;

use Illusiard\Psr7Crypt\Enum\MediaType;

final readonly class ApplicationInfoResolver
{
    public function getApplicationInfo(MediaType $mediaType): string
    {
        return match ($mediaType) {
            MediaType::Image    => 'WhatsApp Image Keys',
            MediaType::Video    => 'WhatsApp Video Keys',
            MediaType::Audio    => 'WhatsApp Audio Keys',
            MediaType::Document => 'WhatsApp Document Keys',
        };
    }
}
