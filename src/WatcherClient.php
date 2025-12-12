<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient;

use CrowdSec\Common\Client\RequestHandler\RequestHandlerInterface;
use CrowdSec\LapiClient\Configuration\Watcher;
use DateTime;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Log\LoggerInterface;

/**
 * Watcher client for LAPI.
 *
 * Handles authentication (login) and alert operations (push, search, delete, getById).
 * Requires a PSR-6 cache implementation to store the authentication token.
 *
 * If you use `auth_type = api_key` you must provide configs `machine_id` and `password`.
 *
 * @psalm-import-type TWatcherConfig from Watcher
 * @psalm-import-type TAlertFull from \CrowdSec\LapiClient\Payload\Alert
 * @psalm-import-type TDecision from \CrowdSec\LapiClient\Payload\Alert
 * @psalm-import-type TEvent from \CrowdSec\LapiClient\Payload\Alert
 * @psalm-import-type TMeta from \CrowdSec\LapiClient\Payload\Alert
 * @psalm-import-type TSource from \CrowdSec\LapiClient\Payload\Alert
 *
 * @psalm-type TLoginResponse = array{
 *     code: positive-int,
 *     expire: non-empty-string,
 *     token: non-empty-string
 * }
 * @psalm-type TSearchQuery = array{
 *     scope?: string,
 *     value?: string,
 *     scenario?: string,
 *     ip?: string,
 *     range?: string,
 *     since?: string,
 *     until?: string,
 *     simulated?: bool,
 *     has_active_decision?: bool,
 *     decision_type?: string,
 *     limit?: int,
 *     origin?: string
 * }
 * @psalm-type TDeleteQuery = array{
 *     scope?: string,
 *     value?: string,
 *     scenario?: string,
 *     ip?: string,
 *     range?: string,
 *     since?: string,
 *     until?: string,
 *     has_active_decision?: bool,
 *     alert_source?: string
 * }
 * @psalm-type TStoredAlert = array{
 *     capacity: int,
 *     created_at: string,
 *     decisions: list<TDecision>,
 *     events: list<TEvent>,
 *     events_count: int,
 *     id: int,
 *     labels: null|array<string, mixed>,
 *     leakspeed: string,
 *     machine_id: string,
 *     message: string,
 *     meta: list<TMeta>,
 *     scenario: string,
 *     scenario_hash: string,
 *     scenario_version: string,
 *     simulated: bool,
 *     source: TSource,
 *     start_at: string,
 *     stop_at: string,
 *     uuid: string
 * }
 */
class WatcherClient extends AbstractLapiClient
{
    private const CACHE_KEY = 'crowdsec_watcher_token';

    /**
     * @var TWatcherConfig
     */
    protected $configs;

    /**
     * @var CacheItemPoolInterface
     */
    private $cache;

    /**
     * @var string[]
     */
    private $scenarios;

    public function __construct(
        array $configs,
        CacheItemPoolInterface $cache,
        array $scenarios = [],
        ?RequestHandlerInterface $requestHandler = null,
        ?LoggerInterface $logger = null
    ) {
        $this->cache = $cache;
        $this->scenarios = $scenarios;
        parent::__construct($configs, $requestHandler, $logger);
    }

    /**
     * @inheritDoc
     */
    protected function getConfiguration(): Configuration
    {
        return new Watcher();
    }

    /**
     * Authenticate with LAPI and retrieve a JWT token.
     *
     * @param string[] $scenarios Optional list of scenarios to register
     *
     * @return TLoginResponse
     *
     * @throws ClientException
     */
    private function login(array $scenarios = []): array
    {
        $data = [
            'scenarios' => $scenarios ?: $this->scenarios,
        ];
        if (isset($this->configs['auth_type']) && Constants::AUTH_KEY === $this->configs['auth_type']) {
            /** @var array{machine_id?: string, password?: string} $configs */
            $configs = $this->configs;
            $data['machine_id'] = $configs['machine_id'] ?? '';
            $data['password'] = $configs['password'] ?? '';
        }

        return $this->manageRequest(
            'POST',
            Constants::WATCHER_LOGIN_ENDPOINT,
            $data
        );
    }

    /**
     * Push alerts to LAPI.
     *
     * @param list<TAlertFull> $alerts
     *
     * @return list<string> Alert IDs
     *
     * @throws ClientException
     */
    public function pushAlerts(array $alerts): array
    {
        $this->ensureAuthenticated();

        return $this->manageRequest(
            'POST',
            Constants::ALERTS_ENDPOINT,
            $alerts
        );
    }

    /**
     * Search for alerts.
     *
     * @param TSearchQuery $query Search parameters:
     *     - scope: Show alerts for this scope
     *     - value: Show alerts for this value (used with scope)
     *     - scenario: Show alerts for this scenario
     *     - ip: IP to search for (shorthand for scope=ip&value=)
     *     - range: Range to search for (shorthand for scope=range&value=)
     *     - since: Search alerts newer than delay (format must be compatible with time.ParseDuration)
     *     - until: Search alerts older than delay (format must be compatible with time.ParseDuration)
     *     - simulated: If set to true, decisions in simulation mode will be returned as well
     *     - has_active_decision: Only return alerts with decisions not expired yet
     *     - decision_type: Restrict results to alerts with decisions matching given type
     *     - limit: Number of alerts to return
     *     - origin: Restrict results to this origin (ie. lists,CAPI,cscli)
     *
     * @return list<TStoredAlert>
     *
     * @throws ClientException
     */
    public function searchAlerts(array $query = []): array
    {
        $this->ensureAuthenticated();

        return $this->manageRequest(
            'GET',
            Constants::ALERTS_ENDPOINT,
            $query
        );
    }

    /**
     * Delete alerts by condition.
     *
     * Can be used only on the same machine as the local API.
     *
     * @param TDeleteQuery $query Delete parameters
     *
     * @throws ClientException
     */
    public function deleteAlerts(array $query = []): array
    {
        $this->ensureAuthenticated();

        return $this->manageRequest(
            'DELETE',
            Constants::ALERTS_ENDPOINT,
            $query
        );
    }

    /**
     * Get a specific alert by ID.
     *
     * @param positive-int $id Alert ID
     *
     * @return ?TStoredAlert Returns null if alert not found
     *
     * @throws ClientException
     */
    public function getAlertById(int $id): ?array
    {
        $this->ensureAuthenticated();

        $result = $this->manageRequest(
            'GET',
            \sprintf('%s/%d', Constants::ALERTS_ENDPOINT, $id)
        );

        // Workaround for muted 404 status
        if (!isset($result['id'])) {
            return null;
        }

        /** @var TStoredAlert */
        return $result;
    }

    /**
     * Ensure the client is authenticated by retrieving/refreshing the token.
     *
     * @throws ClientException
     */
    private function ensureAuthenticated(): void
    {
        $token = $this->retrieveToken();
        if (null === $token) {
            throw new ClientException('Authentication failed');
        }
        $this->headers['Authorization'] = "Bearer $token";
    }

    /**
     * Retrieve the authentication token from cache or login to get a new one.
     */
    private function retrieveToken(): ?string
    {
        $cacheItem = $this->cache->getItem(self::CACHE_KEY);

        if (!$cacheItem->isHit()) {
            $tokenInfo = $this->login();
            if (200 !== $tokenInfo['code']) {
                return null;
            }
            \assert(isset($tokenInfo['token']));
            $cacheItem
                ->set($tokenInfo['token'])
                ->expiresAt(new DateTime($tokenInfo['expire']));
            $this->cache->save($cacheItem);
        }

        return $cacheItem->get();
    }
}
