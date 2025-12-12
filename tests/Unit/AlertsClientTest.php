<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\Tests\Unit;

use CrowdSec\Common\Client\HttpMessage\Response;
use CrowdSec\LapiClient\AlertsClient;
use CrowdSec\LapiClient\ClientException;
use CrowdSec\LapiClient\Constants;
use CrowdSec\LapiClient\Storage\TokenStorageInterface;
use CrowdSec\LapiClient\Tests\MockedData;
use CrowdSec\LapiClient\Tests\PHPUnitUtil;

/**
 * @covers \CrowdSec\LapiClient\AlertsClient::__construct
 * @covers \CrowdSec\LapiClient\AlertsClient::push
 * @covers \CrowdSec\LapiClient\AlertsClient::search
 * @covers \CrowdSec\LapiClient\AlertsClient::delete
 * @covers \CrowdSec\LapiClient\AlertsClient::getById
 * @covers \CrowdSec\LapiClient\AlertsClient::login
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
final class AlertsClientTest extends AbstractClient
{
    private function createTokenStorage(string $token = 'test-token'): TokenStorageInterface
    {
        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->method('retrieveToken')->willReturn($token);

        return $tokenStorage;
    }

    private function createFailingTokenStorage(): TokenStorageInterface
    {
        $tokenStorage = $this->createMock(TokenStorageInterface::class);
        $tokenStorage->method('retrieveToken')->willReturn(null);

        return $tokenStorage;
    }

    public function testAlertsClientInit()
    {
        $tokenStorage = $this->createTokenStorage();
        $client = new AlertsClient($this->configs, $tokenStorage);

        $this->assertInstanceOf(
            AlertsClient::class,
            $client,
            'AlertsClient should be instantiated'
        );
    }

    public function testPush()
    {
        $mockCurl = $this->getCurlMock(['handle']);
        $tokenStorage = $this->createTokenStorage();

        $mockClient = $this->getMockBuilder(AlertsClient::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([
                'configs' => $this->configs,
                'tokenStorage' => $tokenStorage,
                'requestHandler' => $mockCurl,
            ])
            ->onlyMethods(['sendRequest'])
            ->getMock();

        $mockCurl->expects($this->exactly(1))->method('handle')->will(
            $this->returnValue(
                new Response(MockedData::ALERTS_PUSH_SUCCESS, MockedData::HTTP_200, [])
            )
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

        $response = $mockClient->push($alerts);

        $this->assertEquals(
            ['1'],
            $response,
            'Should return alert IDs'
        );
    }

    public function testSearch()
    {
        $mockCurl = $this->getCurlMock(['handle']);
        $tokenStorage = $this->createTokenStorage();

        $mockClient = $this->getMockBuilder(AlertsClient::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([
                'configs' => $this->configs,
                'tokenStorage' => $tokenStorage,
                'requestHandler' => $mockCurl,
            ])
            ->onlyMethods(['sendRequest'])
            ->getMock();

        $mockCurl->expects($this->exactly(1))->method('handle')->will(
            $this->returnValue(
                new Response(MockedData::ALERTS_SEARCH_SUCCESS, MockedData::HTTP_200, [])
            )
        );

        $response = $mockClient->search(['scope' => 'ip', 'value' => '1.2.3.4']);

        $this->assertIsArray($response);
    }

    public function testDelete()
    {
        $mockCurl = $this->getCurlMock(['handle']);
        $tokenStorage = $this->createTokenStorage();

        $mockClient = $this->getMockBuilder(AlertsClient::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([
                'configs' => $this->configs,
                'tokenStorage' => $tokenStorage,
                'requestHandler' => $mockCurl,
            ])
            ->onlyMethods(['sendRequest'])
            ->getMock();

        $mockCurl->expects($this->exactly(1))->method('handle')->will(
            $this->returnValue(
                new Response(MockedData::ALERTS_DELETE_SUCCESS, MockedData::HTTP_200, [])
            )
        );

        $response = $mockClient->delete(['scope' => 'ip', 'value' => '1.2.3.4']);

        $this->assertIsArray($response);
    }

    public function testGetById()
    {
        $mockCurl = $this->getCurlMock(['handle']);
        $tokenStorage = $this->createTokenStorage();

        $mockClient = $this->getMockBuilder(AlertsClient::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([
                'configs' => $this->configs,
                'tokenStorage' => $tokenStorage,
                'requestHandler' => $mockCurl,
            ])
            ->onlyMethods(['sendRequest'])
            ->getMock();

        $mockCurl->expects($this->exactly(1))->method('handle')->will(
            $this->returnValue(
                new Response(MockedData::ALERT_BY_ID_SUCCESS, MockedData::HTTP_200, [])
            )
        );

        $response = $mockClient->getById(1);

        $this->assertIsArray($response);
        $this->assertEquals(1, $response['id']);
    }

    public function testGetByIdNotFound()
    {
        $mockCurl = $this->getCurlMock(['handle']);
        $tokenStorage = $this->createTokenStorage();

        $mockClient = $this->getMockBuilder(AlertsClient::class)
            ->enableOriginalConstructor()
            ->setConstructorArgs([
                'configs' => $this->configs,
                'tokenStorage' => $tokenStorage,
                'requestHandler' => $mockCurl,
            ])
            ->onlyMethods(['sendRequest'])
            ->getMock();

        $mockCurl->expects($this->exactly(1))->method('handle')->will(
            $this->returnValue(
                new Response(MockedData::ALERT_NOT_FOUND, MockedData::HTTP_200, [])
            )
        );

        $response = $mockClient->getById(999);

        $this->assertNull($response);
    }

    public function testLoginFailure()
    {
        $tokenStorage = $this->createFailingTokenStorage();

        $client = new AlertsClient($this->configs, $tokenStorage);

        $error = '';
        try {
            $client->search([]);
        } catch (ClientException $e) {
            $error = $e->getMessage();
        }

        PHPUnitUtil::assertRegExp(
            $this,
            '/Login fail/',
            $error,
            'Should throw ClientException on login failure'
        );
    }
}