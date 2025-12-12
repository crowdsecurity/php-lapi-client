<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\Tests\Integration;

use CrowdSec\LapiClient\AlertsClient;
use CrowdSec\LapiClient\Constants;
use CrowdSec\LapiClient\Payload\Alert;
use CrowdSec\LapiClient\Storage\TokenStorage;
use CrowdSec\LapiClient\Tests\Constants as TestConstants;
use CrowdSec\LapiClient\WatcherClient;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * @note You must delete all alerts manually before running this TestCase. Command: `cscli alerts delete --all`.
 *
 * @coversDefaultClass \CrowdSec\LapiClient\AlertsClient
 */
final class AlertsClientTest extends TestCase
{
    private const DT_FORMAT = 'Y-m-dTH:i:sZ';

    /**
     * @var array
     */
    protected $configs;
    /**
     * @var string
     */
    protected $useTls;

    /**
     * @var AlertsClient
     */
    protected $alertsClient;

    protected function setUp(): void
    {
        $watcherConfigs = [
            'auth_type' => $this->useTls ? Constants::AUTH_TLS : Constants::AUTH_KEY,
            'api_key' => getenv('BOUNCER_KEY'),
            'api_url' => getenv('LAPI_URL'),
            'appsec_url' => getenv('APPSEC_URL'),
            'user_agent_suffix' => TestConstants::USER_AGENT_SUFFIX,
        ];

        $watcherConfigs['machine_id'] = getenv('MACHINE_ID') ?: 'watcherLogin';
        $watcherConfigs['password'] = getenv('PASSWORD') ?: 'watcherPassword';

        $this->configs = $watcherConfigs;

        $watcher = new WatcherClient($this->configs);
        $tokenStorage = new TokenStorage($watcher, new ArrayAdapter());
        $this->alertsClient = new AlertsClient($this->configs, $tokenStorage);
    }

    /**
     * @covers ::push
     */
    public function testPush(): array
    {
        $now = new \DateTimeImmutable();
        $alert01 = new Alert(
            [
                'scenario' => 'crowdsec-lapi-test/with-decision',
                'scenario_hash' => 'alert01',
                'scenario_version' => '1.0',
                'message' => 'alert01',
                'events_count' => 3,
                'start_at' => $now->format(self::DT_FORMAT),
                'stop_at' => $now
                    ->add(new \DateInterval('PT4H'))
                    ->format(self::DT_FORMAT),
                'capacity' => 10,
                'leakspeed' => '10/1s',
                'simulated' => false,
                'remediation' => false,
            ],
            // source
            [
                'scope' => 'ip',
                'value' => '1.1.0.1',
                'as_number' => 'AS12345',
                'as_name' => 'EXAMPLE-AS',
                'cn' => 'US',
                'latitude' => 40.7128,
                'longitude' => -74.0060,
            ],
            // events
            [
                [
                    'meta' => [
                        ['key' => 'path', 'value' => '/alert11'],
                    ],
                    'timestamp' => $now->format(self::DT_FORMAT),
                ],
            ],
            // decisions
            [
                [
                    'origin' => 'lapi',
                    'type' => 'ban',
                    'scope' => 'ip',
                    'value' => '1.1.0.1',
                    'duration' => '4h',
                    'until' => $now
                        ->add(new \DateInterval('PT4H'))
                        ->format(self::DT_FORMAT),
                    'scenario' => 'crowdsec-lapi-test/with-decision',
                ],
            ],
            [
                ['key' => 'service', 'value' => 'phpunit'],
            ],
            ['http', 'probing']
        );
        $alert02 = new Alert(
            [
                'scenario' => 'crowdsec-lapi-test/with-decision',
                'scenario_hash' => 'alert02',
                'scenario_version' => '1.0',
                'message' => 'alert02',
                'events_count' => 3,
                'start_at' => $now->format(self::DT_FORMAT),
                'stop_at' => $now
                    ->add(new \DateInterval('PT4H'))
                    ->format(self::DT_FORMAT),
                'capacity' => 10,
                'leakspeed' => '10/1s',
                'simulated' => true,
                'remediation' => true,
            ],
            // source
            [
                'scope' => 'range',
                'value' => '1.1.0.0/16',
                'as_number' => 'AS12345',
                'as_name' => 'EXAMPLE-AS',
                'cn' => 'US',
                'latitude' => 40.7128,
                'longitude' => -74.0060,
            ],
            // events
            [
                [
                    'meta' => [
                        ['key' => 'path', 'value' => '/alert12'],
                    ],
                    'timestamp' => $now->format(self::DT_FORMAT),
                ],
            ],
            // decisions
            [
                [
                    'origin' => 'phpunit',
                    'type' => 'captcha',
                    'scope' => 'range',
                    'value' => '1.1.0.0/16',
                    'duration' => '4h',
                    'until' => $now
                        ->add(new \DateInterval('PT4H'))
                        ->format(self::DT_FORMAT),
                    'scenario' => 'crowdsec-lapi-test/with-decision',
                ],
            ]
        );
        $alert11 = new Alert(
            [
                'scenario' => 'crowdsec-lapi-test/integration11',
                'scenario_hash' => 'alert11',
                'scenario_version' => '1.0',
                'message' => 'alert10',
                'events_count' => 3,
                'start_at' => $now->format(self::DT_FORMAT),
                'stop_at' => $now
                    ->add(new \DateInterval('PT4H'))
                    ->format(self::DT_FORMAT),
                'capacity' => 11,
                'leakspeed' => '10/2s',
                'simulated' => false,
                'remediation' => false,
            ],
            // source
            [
                'scope' => 'ip',
                'value' => '2.0.1.1',
                'as_number' => 'AS12345',
                'as_name' => 'EXAMPLE-AS',
                'cn' => 'US',
                'latitude' => 40.7128,
                'longitude' => -74.0060,
            ],
            // events
            [
                [
                    'meta' => [
                        ['key' => 'path', 'value' => '/alert21'],
                    ],
                    'timestamp' => $now->format(self::DT_FORMAT),
                ],
            ]
        );
        $alert12 = new Alert(
            [
                'scenario' => 'crowdsec-lapi-test/integration12',
                'scenario_hash' => 'alert12',
                'scenario_version' => '1.0',
                'message' => 'alert12',
                'events_count' => 3,
                'start_at' => $now->format(self::DT_FORMAT),
                'stop_at' => $now
                    ->add(new \DateInterval('PT4H'))
                    ->format(self::DT_FORMAT),
                'capacity' => 12,
                'leakspeed' => '10/2s',
                'simulated' => true,
                'remediation' => true,
            ],
            // source
            [
                'scope' => 'range',
                'value' => '2.0.0.0/16',
                'as_number' => 'AS12345',
                'as_name' => 'EXAMPLE-AS',
                'cn' => 'US',
                'latitude' => 40.7128,
                'longitude' => -74.0060,
            ],
            // events
            [
                [
                    'meta' => [
                        ['key' => 'path', 'value' => '/alert21'],
                    ],
                    'timestamp' => $now->format(self::DT_FORMAT),
                ],
            ]
        );
        $result = $this->alertsClient->push([
            // with decisions
            $alert01,
            $alert02,
            // without decisions
            $alert11,
            $alert12,
        ]);
        self::assertIsArray($result);
        self::assertCount(4, $result);

        return $result;
    }

    /**
     * @covers ::search
     *
     * @depends      testPush
     *
     * @dataProvider searchProvider
     */
    public function testSearch(array $query, int $expectedCount): void
    {
        $result = $this->alertsClient->search($query);
        self::assertCount($expectedCount, $result);
    }

    public static function searchProvider(): iterable
    {
        yield 'empty' => [
            [],
            4,
        ];

        yield 'ip - no' => [
            ['ip' => '19.17.11.7'],
            0,
        ];

        yield 'ip - 1.1.0.1' => [
            ['ip' => '1.1.0.1'],
            // alert01 (scope=ip;value=1.1.0.1 +decision) and alert02(scope=range;value=1.1.0.0/16 +decision)
            2,
        ];
        yield 'ip - 2.0.1.1' => [
            ['ip' => '2.0.1.1'], // alert12 (range no decision)
            1,
        ];

        yield 'scope - ip' => [
            ['scope' => 'ip'],
            2,
        ];
        yield 'scope - range' => [
            ['scope' => 'range'],
            2,
        ];

        yield 'scope - ip:1.1.0.1' => [
            ['scope' => 'ip', 'value' => '1.1.0.1'],
            1,
        ];

        yield 'scenario' => [
            ['scenario' => 'crowdsec-lapi-test/with-decision'],
            2,
        ];

        // has_active_decision is a FILTER: true = only with decisions, false = only without
        yield 'has_active_decision=true' => [
            ['has_active_decision' => 'true'],
            3, // alert01, alert02 have decisions; alert02 simulated also counted
        ];

        yield 'has_active_decision=false' => [
            ['has_active_decision' => 'false'],
            1, // alert11 only (alert12 is simulated and excluded by default)
        ];
        // simulated is an INCLUSION flag: true = include simulated, false = exclude simulated
        yield 'simulated=true' => [
            ['simulated' => 'true'],
            4, // All alerts (both simulated and non-simulated)
        ];
        yield 'simulated=false' => [
            ['simulated' => 'false'],
            2, // Only non-simulated: alert01, alert11
        ];
        yield 'since -1h' => [
            [
                'since' => '-1h',
            ],
            0,
        ];
        yield 'since 1m' => [
            ['since' => '1m'],
            4, // All alerts were just created
        ];
        yield 'since 1h' => [
            ['since' => '10h'],
            4,
        ];

        yield 'until -1h' => [
            ['until' => '-1h'],
            4,
        ];
        yield 'until 1s' => [
            ['until' => '1s'],
            4,
        ];
        yield 'until 1h' => [
            ['until' => '1h'],
            0,
        ];
        yield 'until 10h' => [
            ['until' => '10h'],
            0,
        ];
        yield 'until 100h' => [
            ['until' => '10h'],
            0,
        ];

        yield 'origin=phpunit' => [
            ['origin' => 'phpunit'],
            1,
        ];
        yield 'decision_type=ban' => [
            ['decision_type' => 'ban'],
            2,
        ];
    }

    /**
     * @depends testPush
     */
    public function testGetById(array $idList): void
    {
        foreach ($idList as $id) {
            self::assertIsNumeric($id);
            $result = $this->alertsClient->getById(\intval($id));
            self::assertIsArray($result);
        }
    }

    public function testAlertInfoNotFound(): void
    {
        $result = $this->alertsClient->getById(\PHP_INT_MAX);
        self::assertNull($result);
    }
}
