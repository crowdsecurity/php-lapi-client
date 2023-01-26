<?php

/** @noinspection DuplicatedCode */

declare(strict_types=1);

namespace CrowdSec\LapiClient\Tests\Unit;

/**
 * Test for FGC request handler.
 *
 * @author    CrowdSec team
 *
 * @see      https://crowdsec.net CrowdSec Official Website
 *
 * @copyright Copyright (c) 2022+ CrowdSec
 * @license   MIT License
 */

use CrowdSec\LapiClient\Bouncer;
use CrowdSec\LapiClient\ClientException;
use CrowdSec\LapiClient\Constants;
use CrowdSec\Common\Client\HttpMessage\Request;
use CrowdSec\Common\Client\RequestHandler\FileGetContents;
use CrowdSec\LapiClient\Tests\Constants as TestConstants;
use CrowdSec\LapiClient\Tests\MockedData;
use CrowdSec\LapiClient\Tests\PHPUnitUtil;

/**
 * @uses \CrowdSec\LapiClient\Configuration::getConfigTreeBuilder
 * @uses \CrowdSec\LapiClient\Bouncer::__construct
 * @uses \CrowdSec\LapiClient\Bouncer::configure
 * @uses \CrowdSec\LapiClient\Bouncer::formatUserAgent
 * @uses \CrowdSec\LapiClient\Bouncer::manageRequest
 * @uses \CrowdSec\LapiClient\Configuration::addConnectionNodes
 * @uses \CrowdSec\LapiClient\Configuration::validate
 *
 * @covers \CrowdSec\LapiClient\Bouncer::getStreamDecisions
 * @covers \CrowdSec\LapiClient\Bouncer::getFilteredDecisions
 */
final class FileGetContentsTest extends AbstractClient
{
    public function testContextConfig()
    {
        $method = 'POST';
        $parameters = ['machine_id' => 'test', 'password' => 'test'];

        $fgcRequestHandler = new FileGetContents();

        $client = new Bouncer($this->configs, $fgcRequestHandler);
        $fgcRequester = $client->getRequestHandler();

        $request = new Request('test-url', $method, ['User-Agent' => TestConstants::USER_AGENT_SUFFIX], $parameters);

        $contextConfig = PHPUnitUtil::callMethod(
            $fgcRequester,
            'createContextConfig',
            [$request]
        );

        $contextConfig['http']['header'] = str_replace("\r", '', $contextConfig['http']['header']);

        $expected = [
            'http' => [
                'method' => $method,
                'header' => 'Accept: application/json
Content-Type: application/json
User-Agent: ' . TestConstants::USER_AGENT_SUFFIX . '
',
                'ignore_errors' => true,
                'content' => '{"machine_id":"test","password":"test"}',
                'timeout' => Constants::API_TIMEOUT,
            ],
            'ssl' => [
                'verify_peer' => false,
            ],
        ];

        $this->assertEquals(
            $expected,
            $contextConfig,
            'Context config must be as expected for POST'
        );

        $method = 'GET';
        $parameters = ['foo' => 'bar', 'crowd' => 'sec'];

        $request = new Request('test-url', $method, ['User-Agent' => TestConstants::USER_AGENT_SUFFIX], $parameters);

        $contextConfig = PHPUnitUtil::callMethod(
            $fgcRequester,
            'createContextConfig',
            [$request]
        );

        $contextConfig['http']['header'] = str_replace("\r", '', $contextConfig['http']['header']);

        $expected = [
            'http' => [
                'method' => $method,
                'header' => 'Accept: application/json
Content-Type: application/json
User-Agent: ' . TestConstants::USER_AGENT_SUFFIX . '
',
                'ignore_errors' => true,
                'timeout' => Constants::API_TIMEOUT,
            ],
            'ssl' => [
                'verify_peer' => false,
            ],
        ];

        $this->assertEquals(
            $expected,
            $contextConfig,
            'Context config must be as expected for GET'
        );

        $configs = $this->tlsConfigs;
        $method = 'POST';
        $parameters = ['machine_id' => 'test', 'password' => 'test'];

        $client = new Bouncer($configs, new FileGetContents($configs));
        $fgcRequester = $client->getRequestHandler();

        $request = new Request('test-url', $method, ['User-Agent' => TestConstants::USER_AGENT_SUFFIX], $parameters);

        $contextConfig = PHPUnitUtil::callMethod(
            $fgcRequester,
            'createContextConfig',
            [$request]
        );

        $contextConfig['http']['header'] = str_replace("\r", '', $contextConfig['http']['header']);

        $expected = [
            'http' => [
                'method' => $method,
                'header' => 'Accept: application/json
Content-Type: application/json
User-Agent: ' . TestConstants::USER_AGENT_SUFFIX . '
',
                'ignore_errors' => true,
                'content' => '{"machine_id":"test","password":"test"}',
                'timeout' => TestConstants::API_TIMEOUT,
            ],
            'ssl' => [
                'verify_peer' => true,
                'local_cert' => 'tls_cert_path_test',
                'local_pk' => 'tls_key_path_test',
                'cafile' => 'tls_ca_cert_path_test',
            ],
        ];

        $this->assertEquals(
            $expected,
            $contextConfig,
            'Context config must be as expected for POST'
        );
    }

    public function testDecisionsStream()
    {
        // Success test
        $mockFGCRequest = $this->getFGCMock(['exec']);
        $mockFGCRequest->method('exec')->will(
            $this->onConsecutiveCalls(
                [
                    'response' => MockedData::DECISIONS_STREAM_LIST,
                    'header' => ['HTTP/1.1 ' . MockedData::HTTP_200 . ' OK'],
                ]
            )
        );

        $client = new Bouncer($this->configs, $mockFGCRequest);
        $decisionsResponse = $client->getStreamDecisions(true);

        $this->assertEquals(
            json_decode(MockedData::DECISIONS_STREAM_LIST, true),
            $decisionsResponse,
            'Success get decisions stream'
        );
    }

    public function testFilteredDecisions()
    {
        // Success test
        $mockFGCRequest = $this->getFGCMock(['exec']);
        $mockFGCRequest->method('exec')->will(
            $this->onConsecutiveCalls(
                [
                    'response' => MockedData::DECISIONS_FILTER,
                    'header' => ['HTTP/1.1 ' . MockedData::HTTP_200 . ' OK'],
                ]
            )
        );

        $client = new Bouncer($this->configs, $mockFGCRequest);
        $decisionsResponse = $client->getFilteredDecisions();

        $this->assertEquals(
            json_decode(MockedData::DECISIONS_FILTER, true),
            $decisionsResponse,
            'Success get decisions stream'
        );
    }
}
