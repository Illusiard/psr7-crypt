<?php

namespace Illusiard\Psr7Crypt\Enum;

enum MediaType: string
{
    case Image    = 'image';
    case Video    = 'video';
    case Audio    = 'audio';
    case Document = 'document';

    public function supportsSidecar(): bool
    {
        return match ($this) {
            self::Video, self::Audio    => true,
            self::Image, self::Document => false,
        };
    }
}
