<?php

namespace Illusiard\Psr7Crypt\Service;

use Illusiard\Psr7Crypt\Enum\MediaType;
use Illusiard\Psr7Crypt\ValueObject\ExpandedMediaKey;
use Illusiard\Psr7Crypt\ValueObject\MediaKey;

final readonly class KeyExpander
{
    public function __construct(
        private ApplicationInfoResolver $applicationInfoResolver = new ApplicationInfoResolver()
    )
    {
    }

    public function expand(MediaKey $mediaKey, MediaType $mediaType): ExpandedMediaKey
    {
        $applicationInfo = $this->applicationInfoResolver->getApplicationInfo($mediaType);
        $expandedKey     = $this->deriveHkdfSha256(
            $mediaKey->getValue(),
            ExpandedMediaKey::LENGTH,
            $applicationInfo
        );

        return new ExpandedMediaKey($expandedKey);
    }

    private function deriveHkdfSha256(string $inputKeyMaterial, int $length, string $info): string
    {
        return hash_hkdf(
            'sha256',
            $inputKeyMaterial,
            $length,
            $info,
            str_repeat("\0", 32)
        );
    }
}
