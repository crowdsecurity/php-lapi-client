<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\Tests\Integration;

use CrowdSec\Common\Client\AbstractClient;
use CrowdSec\LapiClient\Constants;
use CrowdSec\LapiClient\Watcher;
use Symfony\Component\Cache\Adapter\ArrayAdapter;

/**
 * Test helper for setting up watcher state in integration tests.
 *
 * Uses Watcher to push alerts with decisions for testing bouncer functionality.
 * Extends AbstractClient to make raw HTTP requests for deleting decisions.
 */
class TestWatcher extends AbstractClient
{
    public const HOURS24 = '+24 hours';

    /** @var Watcher */
    private $watcher;

    /** @var string */
    private $token;

    /** @var array */
    protected $headers = [];

    public function __construct(array $configs)
    {
        $agentTlsPath = getenv('AGENT_TLS_PATH');
        if (!$agentTlsPath) {
            throw new \Exception('Using TLS auth for agent is required. Please set AGENT_TLS_PATH env.');
        }
        $configs['auth_type'] = Constants::AUTH_TLS;
        $configs['tls_cert_path'] = $agentTlsPath . '/agent.pem';
        $configs['tls_key_path'] = $agentTlsPath . '/agent-key.pem';
        $configs['tls_verify_peer'] = false;

        $cache = new ArrayAdapter();
        $this->watcher = new Watcher($configs, $cache);

        $this->headers = ['User-Agent' => 'LAPI_WATCHER_TEST/' . Constants::VERSION];

        parent::__construct($configs);
    }

    /** Set the initial watcher state */
    public function setInitialState(): void
    {
        $this->deleteAllAlerts();
        $now = new \DateTime();
        $this->addDecision($now, '12h', '+12 hours', TestHelpers::BAD_IP, 'captcha');
        $this->addDecision($now, '24h', self::HOURS24, TestHelpers::BAD_IP . '/' . TestHelpers::IP_RANGE, 'ban');
        $this->addDecision($now, '24h', '+24 hours', TestHelpers::JAPAN, 'captcha', Constants::SCOPE_COUNTRY);
    }

    /** Set the second watcher state */
    public function setSecondState(): void
    {
        $this->deleteAllAlerts();
        $now = new \DateTime();
        $this->addDecision($now, '36h', '+36 hours', TestHelpers::NEWLY_BAD_IP, 'ban');
        $this->addDecision(
            $now,
            '48h',
            '+48 hours',
            TestHelpers::NEWLY_BAD_IP . '/' . TestHelpers::IP_RANGE,
            'captcha'
        );
        $this->addDecision($now, '24h', self::HOURS24, TestHelpers::JAPAN, 'captcha', Constants::SCOPE_COUNTRY);
        $this->addDecision($now, '24h', self::HOURS24, TestHelpers::IP_JAPAN, 'ban');
        $this->addDecision($now, '24h', self::HOURS24, TestHelpers::IP_FRANCE, 'ban');
    }

    public function deleteAllAlerts(): void
    {
        $this->watcher->deleteAlerts([]);
    }

    /**
     * Delete all decisions.
     *
     * This uses a raw HTTP request since Watcher doesn't have a method for
     * deleting decisions (decisions are managed through the bouncer endpoint).
     */
    public function deleteAllDecisions(): void
    {
        $this->ensureLogin();

        $this->request(
            'DELETE',
            Constants::DECISIONS_FILTER_ENDPOINT,
            [],
            $this->headers
        );
    }

    /**
     * Ensure we have a valid token by triggering a watcher operation.
     */
    private function ensureLogin(): void
    {
        if (!$this->token) {
            // Trigger authentication by searching for alerts (this will login internally)
            $this->watcher->searchAlerts(['limit' => 1]);

            // Now we need to get the token - we'll do a login call and get it from there
            // Actually, we can't get the token from Watcher since login is private.
            // We need to do our own login call.
            $loginResponse = $this->request(
                'POST',
                Constants::WATCHER_LOGIN_ENDPOINT,
                ['scenarios' => []],
                $this->headers
            );

            $this->token = $loginResponse['token'] ?? '';
            $this->headers['Authorization'] = 'Bearer ' . $this->token;
        }
    }

    protected function getFinalScope(string $scope, string $value): string
    {
        $scope = (Constants::SCOPE_IP === $scope && 2 === count(explode('/', $value))) ? Constants::SCOPE_RANGE :
            $scope;

        /**
         * Must use capital first letter as the crowdsec agent seems to query with first capital letter
         * during getStreamDecisions.
         *
         * @see https://github.com/crowdsecurity/crowdsec/blob/ae6bf3949578a5f3aa8ec415e452f15b404ba5af/pkg/database/decisions.go#L56
         */
        return ucfirst($scope);
    }

    public function addDecision(
        \DateTime $now,
        string $durationString,
        string $dateTimeDurationString,
        string $value,
        string $type,
        string $scope = Constants::SCOPE_IP
    ): void {
        $stopAt = (clone $now)->modify($dateTimeDurationString)->format('Y-m-d\TH:i:s.000\Z');
        $startAt = $now->format('Y-m-d\TH:i:s.000\Z');

        $alert = [
            'capacity' => 0,
            'decisions' => [
                [
                    'duration' => $durationString,
                    'origin' => 'cscli',
                    'scenario' => $type . ' for scope/value (' . $scope . '/' . $value . ') for '
                        . $durationString . ' for PHPUnit tests',
                    'scope' => $this->getFinalScope($scope, $value),
                    'type' => $type,
                    'value' => $value,
                ],
            ],
            'events' => [],
            'events_count' => 1,
            'labels' => null,
            'leakspeed' => '0',
            'message' => 'setup for PHPUnit tests',
            'scenario' => 'setup for PHPUnit tests',
            'scenario_hash' => '',
            'scenario_version' => '',
            'simulated' => false,
            'source' => [
                'scope' => $this->getFinalScope($scope, $value),
                'value' => $value,
            ],
            'start_at' => $startAt,
            'stop_at' => $stopAt,
        ];

        $this->watcher->pushAlerts([$alert]);
    }
}
