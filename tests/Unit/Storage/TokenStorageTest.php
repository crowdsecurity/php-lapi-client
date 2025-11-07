<?php

namespace CrowdSec\LapiClient\Tests\Unit\Storage;

use CrowdSec\LapiClient\Storage\TokenStorage;
use CrowdSec\LapiClient\WatcherClient;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * @coversDefaultClass \CrowdSec\LapiClient\Storage\TokenStorage
 */
final class TokenStorageTest extends TestCase
{
    public function testLoginSuccess(): void
    {
        $watcher = $this->createMock(WatcherClient::class);
        $expire = time() + 3600;
        $watcher
            ->expects(self::once())
            ->method('login')
            ->willReturn([
                'code' => 200,
                'expire' => $expire,
                'token' => 'j.w.t',
            ]);
        $cache = new ArrayAdapter();
        $storage = new TokenStorage($watcher, $cache);
        self::assertSame('j.w.t', $storage->retrieveToken());
        self::assertTrue($cache->hasItem('crowdsec_token'));
        $ci = $cache->getItem('crowdsec_token');
        self::assertSame('j.w.t', $ci->get());
    }
}
