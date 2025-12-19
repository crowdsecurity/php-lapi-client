<?php

namespace CrowdSec\LapiClient\Tests\Unit\Payload;

use CrowdSec\LapiClient\Payload\Alert;
use PHPUnit\Framework\TestCase;

/**
 * @covers \CrowdSec\LapiClient\Payload\Alert::__construct
 * @covers \CrowdSec\LapiClient\Payload\Alert::toArray
 * @covers \CrowdSec\LapiClient\Payload\Alert::fromArray
 * @covers \CrowdSec\LapiClient\Payload\Alert::jsonSerialize
 * @covers \CrowdSec\LapiClient\Payload\Alert::configureDecisions
 * @covers \CrowdSec\LapiClient\Payload\Alert::configureEvents
 * @covers \CrowdSec\LapiClient\Payload\Alert::configureMeta
 * @covers \CrowdSec\LapiClient\Payload\Alert::configureProperties
 * @covers \CrowdSec\LapiClient\Payload\Alert::configureSource
 * @covers \CrowdSec\LapiClient\Payload\Alert::handleList
 * @covers \CrowdSec\LapiClient\Configuration\Alert::getConfigTreeBuilder
 * @covers \CrowdSec\LapiClient\Configuration\Alert\Decision::getConfigTreeBuilder
 * @covers \CrowdSec\LapiClient\Configuration\Alert\Event::getConfigTreeBuilder
 * @covers \CrowdSec\LapiClient\Configuration\Alert\Meta::getConfigTreeBuilder
 * @covers \CrowdSec\LapiClient\Configuration\Alert\Source::getConfigTreeBuilder
 */
class AlertTest extends TestCase
{
    /**
     * @dataProvider dpConstruct
     */
    public function testConstruct(array $in, array $expected): void
    {
        $alert = new Alert(
            $in ?? [],
            $in['source'] ?? null,
            $in['events'] ?? [],
            $in['decisions'] ?? [],
            $in['meta'] ?? [],
            $in['labels'] ?? []
        );
        self::assertEquals($expected, $alert->toArray());
    }

    public function dpConstruct(): iterable
    {
        $base = [
            'scenario' => 'crowdsecurity/http-probing',
            'scenario_hash' => 'abc123',
            'scenario_version' => '1.0',
            'message' => 'Probing detected',
            'events_count' => 3,
            'start_at' => '2025-01-01T00:00:00Z',
            'stop_at' => '2025-01-01T00:10:00Z',
            'capacity' => 10,
            'leakspeed' => '10/1s',
            'simulated' => false,
            'remediation' => true,
            'source' => [
                'scope' => 'ip',
                'value' => '1.2.3.4',
                'ip' => '1.2.3.4',
                'range' => '1.2.3.4/32',
                'as_number' => 'AS12345',
                'as_name' => 'EXAMPLE-AS',
                'cn' => 'US',
                'latitude' => 40.7128,
                'longitude' => -74.0060,
            ],
            'decisions' => [
                [
                    'origin' => 'lapi',
                    'type' => 'ban',
                    'scope' => 'ip',
                    'value' => '1.2.3.4',
                    'duration' => '4h',
                    'until' => '2025-01-01T04:00:00Z',
                    'scenario' => 'crowdsecurity/http-probing',
                ],
            ],
            'events' => [
                [
                    'meta' => [
                        ['key' => 'path', 'value' => '/admin'],
                    ],
                    'timestamp' => '2025-01-01T00:00:01Z',
                ],
            ],
            'meta' => [
                ['key' => 'service', 'value' => 'nginx'],
            ],
            'labels' => ['http', 'probing'],
        ];
        yield 'full example' => [
            $base,
            $base,
        ];

        $minimal = $base;
        unset(
            $minimal['event'],
            $minimal['decisions'],
            $minimal['source'],
            $minimal['meta'],
            $minimal['labels']
        );
        yield 'minimal example' => [
            $minimal,
            $minimal,
        ];
    }

    public function testFromArray(): void
    {
        $data = [
            'scenario' => 'crowdsecurity/http-probing',
            'scenario_hash' => 'abc123',
            'scenario_version' => '1.0',
            'message' => 'Probing detected',
            'events_count' => 3,
            'start_at' => '2025-01-01T00:00:00Z',
            'stop_at' => '2025-01-01T00:10:00Z',
            'capacity' => 10,
            'leakspeed' => '10/1s',
            'simulated' => false,
            'remediation' => true,
            'source' => [
                'scope' => 'ip',
                'value' => '1.2.3.4',
            ],
            'events' => [
                [
                    'meta' => [
                        ['key' => 'path', 'value' => '/admin'],
                    ],
                    'timestamp' => '2025-01-01T00:00:01Z',
                ],
            ],
            'decisions' => [
                [
                    'origin' => 'lapi',
                    'type' => 'ban',
                    'scope' => 'ip',
                    'value' => '1.2.3.4',
                    'duration' => '4h',
                    'scenario' => 'crowdsecurity/http-probing',
                ],
            ],
            'meta' => [
                ['key' => 'service', 'value' => 'nginx'],
            ],
            'labels' => ['http'],
        ];

        $alert = Alert::fromArray($data);

        self::assertEquals($data, $alert->toArray());
    }

    public function testJsonSerialize(): void
    {
        $data = [
            'scenario' => 'crowdsecurity/http-probing',
            'scenario_hash' => 'abc123',
            'scenario_version' => '1.0',
            'message' => 'Probing detected',
            'events_count' => 3,
            'start_at' => '2025-01-01T00:00:00Z',
            'stop_at' => '2025-01-01T00:10:00Z',
            'capacity' => 10,
            'leakspeed' => '10/1s',
            'simulated' => false,
            'remediation' => true,
            'events' => [],
        ];

        $alert = new Alert(
            $data,
            null,
            [],
            [],
            [],
            []
        );

        $json = json_encode($alert);
        $decoded = json_decode($json, true);

        self::assertEquals($data, $decoded);
    }
}
