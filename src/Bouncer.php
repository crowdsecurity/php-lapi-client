<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient;

use CrowdSec\LapiClient\RequestHandler\RequestHandlerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Config\Definition\Processor;

/**
 * The Bouncer Client.
 *
 * @author    CrowdSec team
 *
 * @see      https://crowdsec.net CrowdSec Official Website
 *
 * @copyright Copyright (c) 2022+ CrowdSec
 * @license   MIT License
 */
class Bouncer extends AbstractClient
{
    /**
     * @var string The decisions endpoint
     */
    public const DECISIONS_FILTER_ENDPOINT = '/v1/decisions';
    /**
     * @var string The decisions stream endpoint
     */
    public const DECISIONS_STREAM_ENDPOINT = '/v1/decisions/stream';
    /**
     * @var array
     */
    protected $configs;
    /**
     * @var array
     */
    private $headers;

    public function __construct(
        array $configs,
        RequestHandlerInterface $requestHandler = null,
        LoggerInterface $logger = null
    ) {
        $this->configure($configs);
        $this->headers = ['User-Agent' => $this->formatUserAgent($this->configs)];
        if (!empty($this->configs['api_key'])) {
            $this->headers['X-Api-Key'] = $this->configs['api_key'];
        }
        parent::__construct($this->configs, $requestHandler, $logger);
    }

    /**
     * Process a decisions call to LAPI with some filter(s).
     *
     * @see https://crowdsecurity.github.io/api_doc/index.html?urls.primaryName=LAPI#/bouncers/getDecisions
     */
    public function getFilteredDecisions(array $filter = []): array
    {
        return $this->manageRequest(
            'GET',
            self::DECISIONS_FILTER_ENDPOINT,
            $filter
        );
    }

    /**
     * Process a decisions stream call to LAPI.
     *
     * @see https://crowdsecurity.github.io/api_doc/index.html?urls.primaryName=LAPI#/bouncers/getDecisionsStream
     */
    public function getStreamDecisions(
        bool $startup,
        array $filter = []
    ): array {
        return $this->manageRequest(
            'GET',
            self::DECISIONS_STREAM_ENDPOINT,
            array_merge(['startup' => $startup ? 'true' : 'false'], $filter)
        );
    }

    /**
     * Process and validate input configurations.
     */
    private function configure(array $configs): void
    {
        $configuration = new Configuration();
        $processor = new Processor();
        $this->configs = $processor->processConfiguration($configuration, [$configs]);
    }

    /**
     * Format User-Agent header. <PHP LAPI client prefix>_<custom suffix>/<vX.Y.Z>.
     */
    private function formatUserAgent(array $configs = []): string
    {
        $userAgentSuffix = !empty($configs['user_agent_suffix']) ? '_' . $configs['user_agent_suffix'] : '';

        return Constants::USER_AGENT_PREFIX . $userAgentSuffix . '/' . Constants::VERSION;
    }

    /**
     * Make a request.
     *
     * @throws ClientException
     */
    private function manageRequest(
        string $method,
        string $endpoint,
        array $parameters = []
    ): array {
        $this->logger->debug('', [
            'type' => 'BOUNCER_CLIENT_REQUEST',
            'method' => $method,
            'endpoint' => $endpoint,
            'parameters' => $parameters,
        ]);

        return $this->request($method, $endpoint, $parameters, $this->headers);
    }
}
