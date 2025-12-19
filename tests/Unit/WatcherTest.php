<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\Tests\Unit;

use CrowdSec\Common\Client\HttpMessage\Response;
use CrowdSec\LapiClient\ClientException;
use CrowdSec\LapiClient\Configuration\Watcher as WatcherConfig;
use CrowdSec\LapiClient\Constants;
use CrowdSec\LapiClient\Tests\MockedData;
use CrowdSec\LapiClient\Tests\PHPUnitUtil;
use CrowdSec\LapiClient\Watcher;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * @covers \CrowdSec\LapiClient\Watcher::__construct
 * @covers \CrowdSec\LapiClient\Watcher::getConfiguration
 * @covers \CrowdSec\LapiClient\Watcher::login
 * @covers \CrowdSec\LapiClient\Watcher::pushAlerts
 * @covers \CrowdSec\LapiClient\Watcher::searchAlerts
 * @covers \CrowdSec\LapiClient\Watcher::deleteAlerts
 * @covers \CrowdSec\LapiClient\Watcher::getAlertById
 * @covers \CrowdSec\LapiClient\Watcher::ensureAuthenticated
 * @covers \CrowdSec\LapiClient\Watcher::retrieveToken
 * @covers \CrowdSec\LapiClient\Configuration\Watcher::getConfigTreeBuilder
 * @covers \CrowdSec\LapiClient\Configuration\Watcher::addWatcherNodes
 * @covers \CrowdSec\LapiClient\Configuration\Watcher::validateApiKey
 *
 * @uses \CrowdSec\LapiClient\AbstractLapiClient::__construct
 * @uses \CrowdSec\LapiClient\AbstractLapiClient::configure
 * @uses \CrowdSec\LapiClient\AbstractLapiClient::getConfiguration
 * @uses \CrowdSec\LapiClient\AbstractLapiClient::formatUserAgent
 * @uses \CrowdSec\LapiClient\AbstractLapiClient::manageRequest
 * @uses \CrowdSec\LapiClient\Configuration::getConfigTreeBuilder
 * @uses \CrowdSec\LapiClient\Configuration::addConnectionNodes
 * @uses \CrowdSec\LapiClient\Configuration::addAppSecNodes
 * @uses \CrowdSec\LapiClient\Configuration::validateTls
 * @uses \CrowdSec\LapiClient\Configuration\Watcher::validateApiKey
 */
final class WatcherTest extends AbstractClient
{
    /**
     * @var ArrayAdapter
     */
    protected $cache;

    protected function setUp(): void
    {
        parent::setUp();
        $this->configs = array_merge($this->configs, [
            'machine_id' => 'test-machine',
            'password' => 'test-password',
        ]);
        $this->cache = new ArrayAdapter();
    }

    public function testWatcherInit()
    {
        $client = new Watcher($this->configs, $this->cache);

        $this->assertInstanceOf(
            Watcher::class,
            $client,
            'Watcher should be instantiated'
        );

        $configuration = PHPUnitUtil::callMethod($client, 'getConfiguration', []);
        $this->assertInstanceOf(
            WatcherConfig::class,
            $configuration,
            'Watcher should use Watcher configuration'
        );
    }

    public function testWatcherInitWithTlsAuth()
    {
        $tlsConfigs = [
            'auth_type' => Constants::AUTH_TLS,
            'tls_cert_path' => '/path/to/cert.pem',
            'tls_key_path' => '/path/to/key.pem',
        ];

        $client = new Watcher($tlsConfigs, $this->cache);

        $this->assertInstanceOf(
            Watcher::class,
            $client,
            'Watcher should be instantiated with TLS auth'
        );
    }

    public function testConfigureValidation()
    {
        // Test missing machine_id
        $error = '';
        try {
            new Watcher([
                'api_key' => 'test-key',
                'password' => 'test-password',
            ], $this->cache);
        } catch (\Exception $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/machine_id and password are required/',
            $error,
            'machine_id should be required for api_key auth'
        );

        // Test missing password
        $error = '';
        try {
            new Watcher([
                'api_key' => 'test-key',
                'machine_id' => 'test-machine',
            ], $this->cache);
        } catch (\Exception $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/machine_id and password are required/',
            $error,
            'password should be required for api_key auth'
        );
    }

    public function testPushAlerts()
    {
        $mockCurl = $this->getCurlMock(['handle']);

        $mockClient = $this->getMockBuilder(Watcher::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([
                'configs' => $this->configs,
                'cache' => $this->cache,
                'scenarios' => [],
                'requestHandler' => $mockCurl,
            ])
            ->onlyMethods(['sendRequest'])
            ->getMock();

        // First call: login, Second call: push alerts
        $mockCurl->expects($this->exactly(2))->method('handle')->willReturnOnConsecutiveCalls(
            new Response(MockedData::LOGIN_SUCCESS, MockedData::HTTP_200, []),
            new Response(MockedData::ALERTS_PUSH_SUCCESS, MockedData::HTTP_200, [])
        );

        $alerts = [
            [
                'scenario' => 'test/scenario',
                'scenario_hash' => 'abc123',
                'scenario_version' => '1.0',
                'message' => 'Test alert',
                'events_count' => 1,
                'start_at' => '2025-01-01T00:00:00Z',
                'stop_at' => '2025-01-01T00:00:01Z',
                'capacity' => 10,
                'leakspeed' => '10/1s',
                'simulated' => false,
                'remediation' => true,
                'events' => [],
            ],
        ];

        $response = $mockClient->pushAlerts($alerts);

        $this->assertEquals(['1'], $response, 'Should return alert IDs');
    }

    public function testSearchAlerts()
    {
        $mockCurl = $this->getCurlMock(['handle']);

        $mockClient = $this->getMockBuilder(Watcher::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([
                'configs' => $this->configs,
                'cache' => $this->cache,
                'scenarios' => [],
                'requestHandler' => $mockCurl,
            ])
            ->onlyMethods(['sendRequest'])
            ->getMock();

        $mockCurl->expects($this->exactly(2))->method('handle')->willReturnOnConsecutiveCalls(
            new Response(MockedData::LOGIN_SUCCESS, MockedData::HTTP_200, []),
            new Response(MockedData::ALERTS_SEARCH_SUCCESS, MockedData::HTTP_200, [])
        );

        $response = $mockClient->searchAlerts(['scope' => 'ip', 'value' => '1.2.3.4']);

        $this->assertIsArray($response);
    }

    public function testDeleteAlerts()
    {
        $mockCurl = $this->getCurlMock(['handle']);

        $mockClient = $this->getMockBuilder(Watcher::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([
                'configs' => $this->configs,
                'cache' => $this->cache,
                'scenarios' => [],
                'requestHandler' => $mockCurl,
            ])
            ->onlyMethods(['sendRequest'])
            ->getMock();

        $mockCurl->expects($this->exactly(2))->method('handle')->willReturnOnConsecutiveCalls(
            new Response(MockedData::LOGIN_SUCCESS, MockedData::HTTP_200, []),
            new Response(MockedData::ALERTS_DELETE_SUCCESS, MockedData::HTTP_200, [])
        );

        $response = $mockClient->deleteAlerts(['scope' => 'ip', 'value' => '1.2.3.4']);

        $this->assertIsArray($response);
    }

    public function testGetAlertById()
    {
        $mockCurl = $this->getCurlMock(['handle']);

        $mockClient = $this->getMockBuilder(Watcher::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([
                'configs' => $this->configs,
                'cache' => $this->cache,
                'scenarios' => [],
                'requestHandler' => $mockCurl,
            ])
            ->onlyMethods(['sendRequest'])
            ->getMock();

        $mockCurl->expects($this->exactly(2))->method('handle')->willReturnOnConsecutiveCalls(
            new Response(MockedData::LOGIN_SUCCESS, MockedData::HTTP_200, []),
            new Response(MockedData::ALERT_BY_ID_SUCCESS, MockedData::HTTP_200, [])
        );

        $response = $mockClient->getAlertById(1);

        $this->assertIsArray($response);
        $this->assertEquals(1, $response['id']);
    }

    public function testGetAlertByIdNotFound()
    {
        $mockCurl = $this->getCurlMock(['handle']);

        $mockClient = $this->getMockBuilder(Watcher::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([
                'configs' => $this->configs,
                'cache' => $this->cache,
                'scenarios' => [],
                'requestHandler' => $mockCurl,
            ])
            ->onlyMethods(['sendRequest'])
            ->getMock();

        $mockCurl->expects($this->exactly(2))->method('handle')->willReturnOnConsecutiveCalls(
            new Response(MockedData::LOGIN_SUCCESS, MockedData::HTTP_200, []),
            new Response(MockedData::ALERT_NOT_FOUND, MockedData::HTTP_200, [])
        );

        $response = $mockClient->getAlertById(999);

        $this->assertNull($response);
    }

    public function testAuthenticationFailure()
    {
        $mockCurl = $this->getCurlMock(['handle']);

        $mockClient = $this->getMockBuilder(Watcher::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([
                'configs' => $this->configs,
                'cache' => $this->cache,
                'scenarios' => [],
                'requestHandler' => $mockCurl,
            ])
            ->onlyMethods(['sendRequest'])
            ->getMock();

        // Return failed login response
        $mockCurl->expects($this->exactly(1))->method('handle')->will(
            $this->returnValue(
                new Response('{"code":401,"message":"Unauthorized"}', MockedData::HTTP_200, [])
            )
        );

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Authentication failed');

        $mockClient->searchAlerts([]);
    }

    public function testTokenCaching()
    {
        $mockCurl = $this->getCurlMock(['handle']);

        // Pre-populate the cache with a valid token
        $cacheItem = $this->cache->getItem('crowdsec_watcher_token');
        $cacheItem->set('cached-test-token');
        $cacheItem->expiresAt(new \DateTime('+1 hour'));
        $this->cache->save($cacheItem);

        $mockClient = $this->getMockBuilder(Watcher::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([
                'configs' => $this->configs,
                'cache' => $this->cache,
                'scenarios' => [],
                'requestHandler' => $mockCurl,
            ])
            ->onlyMethods(['sendRequest'])
            ->getMock();

        // No login calls - only two alert calls using cached token
        $mockCurl->expects($this->exactly(2))->method('handle')->willReturnOnConsecutiveCalls(
            new Response(MockedData::ALERTS_SEARCH_SUCCESS, MockedData::HTTP_200, []),
            new Response(MockedData::ALERTS_SEARCH_SUCCESS, MockedData::HTTP_200, [])
        );

        // Both calls should use cached token (no login)
        $mockClient->searchAlerts([]);
        $mockClient->searchAlerts([]);
    }
}