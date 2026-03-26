<?php

namespace Illusiard\Psr7Crypt\Tests\Unit\Service;

use Illusiard\Psr7Crypt\Exception\SidecarNotReadyException;
use Illusiard\Psr7Crypt\Service\SidecarAccumulator;
use PHPUnit\Framework\TestCase;
use Random\RandomException;

final class SidecarAccumulatorTest extends TestCase
{
    public function testItBuildsExpectedSidecarForVideoSampleCiphertext(): void
    {
        $videoCiphertext = substr(
            file_get_contents(__DIR__ . '/../../../task/samples/VIDEO.encrypted'),
            0,
            -10
        );

        $videoMac = substr(file_get_contents(__DIR__ . '/../../../task/samples/VIDEO.encrypted'), -10);

        $expandedMediaKey = hex2bin(
            'c4e6a83a7011cf7824679675d2f10e9e' .
            '8ce388d72275ae064ad1a427840788a0c75a922937c734dbbb7e04c7c64f49af' .
            'eed48c020b22b3050370f0ba58096a342fc64ea290ac45c314718292403d5f05' .
            '55e141f9fec0196767165f402fee5ecbd8265659b0e59733062bc8b2c035efcc'
        );
        $iv               = substr($expandedMediaKey, 0, 16);
        $macKey           = substr($expandedMediaKey, 48, 32);

        $accumulator = new SidecarAccumulator($macKey);
        $accumulator->appendInitializationVector($iv);
        $offset      = 0;

        foreach ([13, 4096, 65535, 8192, 120000, 200000] as $chunkLength) {
            $chunk = substr($videoCiphertext, $offset, $chunkLength);

            if ($chunk === '') {
                break;
            }

            $accumulator->appendCiphertext($chunk);
            $offset += strlen($chunk);
        }

        if ($offset < strlen($videoCiphertext)) {
            $accumulator->appendCiphertext(substr($videoCiphertext, $offset));
        }

        $accumulator->appendMessageAuthenticationCode($videoMac);
        $accumulator->finalize();

        self::assertStringEqualsFile(
            __DIR__ . '/../../../task/samples/VIDEO.sidecar',
            $accumulator->getSidecar()->getValue()
        );
        self::assertSame(7, $accumulator->getSidecar()->getChunkCount());
    }

    /**
     * @return void
     * @throws RandomException
     */
    public function testItFailsWhenSidecarIsRequestedBeforeFinalization(): void
    {
        $accumulator = new SidecarAccumulator(random_bytes(32));
        $accumulator->appendCiphertext('ciphertext');

        $this->expectException(SidecarNotReadyException::class);
        $accumulator->getSidecar();
    }
}
