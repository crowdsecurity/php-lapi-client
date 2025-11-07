<?php

namespace CrowdSec\LapiClient;

use CrowdSec\Common\Client\AbstractClient;
use CrowdSec\Common\Client\ClientException as CommonClientException;
use CrowdSec\Common\Client\RequestHandler\RequestHandlerInterface;
use CrowdSec\Common\Client\TimeoutException as CommonTimeoutException;
use Psr\Log\LoggerInterface;
use Symfony\Component\Config\Definition\Processor;

/**
 * @psalm-import-type TBouncerConfig from Configuration
 */
abstract class AbstractLapiClient extends AbstractClient
{
    /**
     * @var TBouncerConfig
     */
    protected $configs;
    /**
     * @var array
     */
    protected $headers;

    public function __construct(
        array $configs,
        ?RequestHandlerInterface $requestHandler = null,
        ?LoggerInterface $logger = null
    ) {
        $this->configure($configs);
        $this->headers = [Constants::HEADER_LAPI_USER_AGENT => $this->formatUserAgent($this->configs)];
        if (!empty($this->configs['api_key'])) {
            $this->headers[Constants::HEADER_LAPI_API_KEY] = $this->configs['api_key'];
        }
        parent::__construct($this->configs, $requestHandler, $logger);
    }

    /**
     * Process and validate input configurations.
     */
    private function configure(array $configs): void
    {
        $configuration = new Configuration();
        $processor = new Processor();
        $this->configs = $processor->processConfiguration($configuration, [$configuration->cleanConfigs($configs)]);
    }

    /**
     * Make a request to LAPI.
     *
     * @throws ClientException
     */
    protected function manageRequest(
        string $method,
        string $endpoint,
        array $parameters = []
    ): array {
        try {
            $this->logger->debug('Now processing a bouncer request', [
                'type' => 'BOUNCER_CLIENT_REQUEST',
                'method' => $method,
                'endpoint' => $endpoint,
                'parameters' => $parameters,
            ]);

            return $this->request($method, $endpoint, $parameters, $this->headers);
        } catch (CommonTimeoutException $e) {
            throw new TimeoutException($e->getMessage(), $e->getCode(), $e);
        } catch (CommonClientException $e) {
            throw new ClientException($e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Make a request to the AppSec component of LAPI.
     *
     * @throws ClientException
     */
    protected function manageAppSecRequest(
        string $method,
        array $headers = [],
        string $rawBody = '',
    ): array {
        try {
            $this->logger->debug('Now processing a bouncer AppSec request', [
                'type' => 'BOUNCER_CLIENT_APPSEC_REQUEST',
                'method' => $method,
                'raw body' => $this->cleanRawBodyForLog($rawBody, 200),
                'raw body length' => strlen($rawBody),
                'headers' => $this->cleanHeadersForLog($headers),
            ]);

            return $this->requestAppSec($method, $headers, $rawBody);
        } catch (CommonTimeoutException $e) {
            throw new TimeoutException($e->getMessage(), $e->getCode(), $e);
        } catch (CommonClientException $e) {
            throw new ClientException($e->getMessage(), $e->getCode(), $e);
        }
    }

    protected function cleanHeadersForLog(array $headers): array
    {
        $cleanedHeaders = $headers;
        if (array_key_exists(Constants::HEADER_APPSEC_API_KEY, $cleanedHeaders)) {
            $cleanedHeaders[Constants::HEADER_APPSEC_API_KEY] = '***';
        }

        return $cleanedHeaders;
    }

    protected function cleanRawBodyForLog(string $rawBody, int $maxLength): string
    {
        return strlen($rawBody) > $maxLength ? substr($rawBody, 0, $maxLength) . '...[TRUNCATED]' : $rawBody;
    }

    /**
     * Format User-Agent header. <PHP LAPI client prefix>_<custom suffix>/<vX.Y.Z>.
     */
    protected function formatUserAgent(array $configs = []): string
    {
        $userAgentSuffix = !empty($configs['user_agent_suffix']) ? '_' . $configs['user_agent_suffix'] : '';
        $userAgentVersion =
            !empty($configs['user_agent_version']) ? $configs['user_agent_version'] : Constants::VERSION;

        return Constants::USER_AGENT_PREFIX . $userAgentSuffix . '/' . $userAgentVersion;
    }
}
