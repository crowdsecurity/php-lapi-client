<?php

namespace CrowdSec\LapiClient\Tests\Unit\Storage;

use CrowdSec\LapiClient\Storage\TokenStorage;
use CrowdSec\LapiClient\WatcherClient;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * @covers \CrowdSec\LapiClient\Storage\TokenStorage::retrieveToken
 * @covers \CrowdSec\LapiClient\Storage\TokenStorage::__construct
 */
final class TokenStorageTest extends TestCase
{
    public function testLoginSuccess(): void
    {
        $watcher = $this->createMock(WatcherClient::class);
        $expire = (new \DateTime('+1 hour'))->format('Y-m-d\TH:i:s\Z');
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

    public function testLoginFailure(): void
    {
        $watcher = $this->createMock(WatcherClient::class);
        $watcher
            ->expects(self::once())
            ->method('login')
            ->willReturn([
                'code' => 401,
                'message' => 'Unauthorized',
            ]);
        $cache = new ArrayAdapter();
        $storage = new TokenStorage($watcher, $cache);
        self::assertNull($storage->retrieveToken());
        self::assertFalse($cache->hasItem('crowdsec_token'));
    }
}
