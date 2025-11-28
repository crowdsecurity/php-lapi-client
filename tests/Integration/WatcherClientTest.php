<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\Tests\Integration;

use CrowdSec\LapiClient\Constants;
use CrowdSec\LapiClient\Tests\Constants as TestConstants;
use CrowdSec\LapiClient\WatcherClient;
use PHPUnit\Framework\TestCase;

/**
 * @coversDefaultClass \CrowdSec\LapiClient\WatcherClient
 */
final class WatcherClientTest extends TestCase
{
    public function testLoginTls(): void
    {
        $agentTlsPath = getenv('AGENT_TLS_PATH');
        if (!$agentTlsPath) {
            throw new \Exception('Using TLS auth for agent is required. Please set AGENT_TLS_PATH env.');
        }
        
        $watcherConfigs = [
            'api_url' => getenv('LAPI_URL'),
            'appsec_url' => getenv('APPSEC_URL'),
            'user_agent_suffix' => TestConstants::USER_AGENT_SUFFIX,
            'auth_type' => Constants::AUTH_TLS,
            'tls_cert_path' => "{$agentTlsPath}/agent.pem",
            'tls_key_path' => "{$agentTlsPath}/agent-key.pem",
            'tls_verify_peer' => false,
        ];

        $watcher = new WatcherClient($watcherConfigs);
        self::assertLoginResult($watcher->login());
    }

    public function testLoginApiKey(): void
    {
        $machineId = getenv('MACHINE_ID') ?: 'watcherLogin';
        $password = getenv('PASSWORD') ?: 'watcherPassword';

        $watcherConfigs = [
            'api_url' => getenv('LAPI_URL'),
            'appsec_url' => getenv('APPSEC_URL'),
            'user_agent_suffix' => TestConstants::USER_AGENT_SUFFIX,
            'auth_type' => Constants::AUTH_KEY,
            'api_key' => getenv('BOUNCER_KEY'),
            'machine_id' => $machineId,
            'password' => $password,
        ];

        $watcher = new WatcherClient($watcherConfigs);
        self::assertLoginResult($watcher->login());
    }

    private static function assertLoginResult(array $data): void
    {
        self::assertArrayHasKey('code', $data);
        self::assertArrayHasKey('expire', $data);
        self::assertArrayHasKey('token', $data);

        self::assertSame(200, $data['code']);
        self::assertMatchesRegularExpression('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/', $data['expire']);
        // JWT
        $parts = explode('.', $data['token']);
        self::assertCount(3, $parts);
        $payloadStr = \base64_decode($parts[1]);
        self::assertNotSame(false, $payloadStr);
        $payload = \json_decode($payloadStr, true);
        self::assertNotEmpty($payload);
        self::assertArrayHasKey('exp', $payload);
        self::assertTrue(\is_int($payload['exp']));
        self::assertArrayHasKey('id', $payload);
        self::assertTrue(\is_string($payload['id']));
        self::assertArrayHasKey('orig_iat', $payload);
        self::assertTrue(\is_int($payload['orig_iat']));
    }
}
