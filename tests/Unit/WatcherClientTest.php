<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\Tests\Unit;

use CrowdSec\Common\Client\HttpMessage\Response;
use CrowdSec\LapiClient\Configuration\Watcher;
use CrowdSec\LapiClient\Constants;
use CrowdSec\LapiClient\Tests\MockedData;
use CrowdSec\LapiClient\Tests\PHPUnitUtil;
use CrowdSec\LapiClient\WatcherClient;

/**
 * @covers \CrowdSec\LapiClient\WatcherClient::getConfiguration
 * @covers \CrowdSec\LapiClient\WatcherClient::login
 * @covers \CrowdSec\LapiClient\Configuration\Watcher::getConfigTreeBuilder
 * @covers \CrowdSec\LapiClient\Configuration\Watcher::addWatcherNodes
 * @covers \CrowdSec\LapiClient\Configuration\Watcher::validateWatcher
 *
 * @uses \CrowdSec\LapiClient\AbstractLapiClient::__construct
 * @uses \CrowdSec\LapiClient\AbstractLapiClient::configure
 * @uses \CrowdSec\LapiClient\AbstractLapiClient::getConfiguration
 * @uses \CrowdSec\LapiClient\AbstractLapiClient::formatUserAgent
 * @uses \CrowdSec\LapiClient\AbstractLapiClient::manageRequest
 * @uses \CrowdSec\LapiClient\Configuration::getConfigTreeBuilder
 * @uses \CrowdSec\LapiClient\Configuration::addConnectionNodes
 * @uses \CrowdSec\LapiClient\Configuration::addAppSecNodes
 * @uses \CrowdSec\LapiClient\Configuration::validate
 */
final class WatcherClientTest extends AbstractClient
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->configs = array_merge($this->configs, [
            'machine_id' => 'test-machine',
            'password' => 'test-password',
        ]);
    }

    public function testWatcherClientInit()
    {
        $client = new WatcherClient($this->configs);

        $this->assertInstanceOf(
            WatcherClient::class,
            $client,
            'WatcherClient should be instantiated'
        );

        $configuration = PHPUnitUtil::callMethod($client, 'getConfiguration', []);
        $this->assertInstanceOf(
            Watcher::class,
            $configuration,
            'WatcherClient should use Watcher configuration'
        );
    }

    public function testLoginParams()
    {
        $mockClient = $this->getMockBuilder(WatcherClient::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs(['configs' => $this->configs])
            ->onlyMethods(['request'])
            ->getMock();

        $mockClient->expects($this->exactly(1))->method('request')
            ->with(
                'POST',
                Constants::WATCHER_LOGIN_ENDPOINT,
                [
                    'scenarios' => ['test/scenario'],
                    'machine_id' => 'test-machine',
                    'password' => 'test-password',
                ],
                $this->anything()
            );

        $mockClient->login(['test/scenario']);
    }

    public function testLoginWithTlsAuth()
    {
        $tlsConfigs = [
            'auth_type' => Constants::AUTH_TLS,
            'tls_cert_path' => '/path/to/cert',
            'tls_key_path' => '/path/to/key',
        ];

        $mockClient = $this->getMockBuilder(WatcherClient::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs(['configs' => $tlsConfigs])
            ->onlyMethods(['request'])
            ->getMock();

        // With TLS auth, machine_id and password should NOT be included
        $mockClient->expects($this->exactly(1))->method('request')
            ->with(
                'POST',
                Constants::WATCHER_LOGIN_ENDPOINT,
                ['scenarios' => []],
                $this->anything()
            );

        $mockClient->login();
    }

    public function testLoginRequest()
    {
        $mockCurl = $this->getCurlMock(['handle']);

        $mockClient = $this->getMockBuilder(WatcherClient::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([
                'configs' => $this->configs,
                'requestHandler' => $mockCurl,
            ])
            ->onlyMethods(['sendRequest'])
            ->getMock();

        $mockCurl->expects($this->exactly(1))->method('handle')->will(
            $this->returnValue(
                new Response(MockedData::LOGIN_SUCCESS, MockedData::HTTP_200, [])
            )
        );

        $response = $mockClient->login(['test/scenario']);

        $this->assertEquals(
            json_decode(MockedData::LOGIN_SUCCESS, true),
            $response,
            'Should return login response'
        );
    }

    public function testConfigureValidation()
    {
        // Test missing machine_id
        $error = '';
        try {
            new WatcherClient([
                'api_key' => 'test-key',
                'password' => 'test-password',
            ]);
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
            new WatcherClient([
                'api_key' => 'test-key',
                'machine_id' => 'test-machine',
            ]);
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
}