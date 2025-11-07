<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient;

use CrowdSec\Common\Client\RequestHandler\RequestHandlerInterface;
use LogicException;
use Psr\Log\LoggerInterface;

/**
 * If you use `auth_type = api_key` you must provide configs `machine_id` and `password`.
 *
 * @psalm-type TLoginResponse = array{
 *     code: positive-int,
 *     expire: non-empty-string,
 *     token: non-empty-string
 * }
 */
class WatcherClient extends AbstractLapiClient
{
    public function __construct(
        array $configs,
        ?RequestHandlerInterface $requestHandler = null,
        ?LoggerInterface $logger = null
    ) {
        if ($configs['auth_type'] === Constants::AUTH_KEY) {
            if (empty($configs['machine_id']) || empty($configs['password'])) {
                throw new LogicException('Missing required config: machine_id or password.');
            }
        }

        parent::__construct($configs, $requestHandler, $logger);
    }

    /**
     * @throws ClientException
     * @return TLoginResponse
     */
    public function login(array $scenarios = []): array
    {
        $data = [
            'scenarios' => $scenarios,
        ];
        if ($this->configs['auth_type'] === Constants::AUTH_KEY) {
            $data['machine_id'] = $this->configs['machine_id'];
            $data['password'] = $this->configs['password'];
        }

        return $this->manageRequest(
            'POST',
            Constants::WATCHER_LOGIN_ENDPOINT,
            $data
        );
    }
}
