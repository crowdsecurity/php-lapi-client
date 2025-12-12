<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient;

use CrowdSec\LapiClient\Configuration\Watcher;

/**
 * If you use `auth_type = api_key` you must provide configs `machine_id` and `password`.
 *
 * @psalm-import-type TWatcherConfig from Watcher
 * @psalm-type TLoginResponse = array{
 *     code: positive-int,
 *     expire: non-empty-string,
 *     token: non-empty-string
 * }
 */
class WatcherClient extends AbstractLapiClient
{
    /**
     * @var TWatcherConfig
     */
    protected $configs;
    /**
     * @inheritDoc
     */
    protected function getConfiguration(): Configuration
    {
        return new Watcher();
    }

    /**
     * @return TLoginResponse
     *
     * @throws ClientException
     */
    public function login(array $scenarios = []): array
    {
        $data = [
            'scenarios' => $scenarios,
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
}
