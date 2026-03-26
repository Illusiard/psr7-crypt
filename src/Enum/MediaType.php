<?php

namespace Illusiard\Psr7Crypt\Enum;

enum MediaType: string
{
    case Image    = 'image';
    case Video    = 'video';
    case Audio    = 'audio';
    case Document = 'document';
}
