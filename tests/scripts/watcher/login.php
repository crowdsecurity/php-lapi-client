<?php

require_once __DIR__ . '/../../../vendor/autoload.php';

use CrowdSec\Common\Logger\ConsoleLog;
use CrowdSec\LapiClient\WatcherClient;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;

$machineId = $argv[1] ?? false;
$password = $argv[2] ?? false;
$lapiUrl = $argv[3] ?? false;
$scenariosJson = $argv[4] ?? '[]';

if (!$machineId || !$password || !$lapiUrl) {
    exit('Params <MACHINE_ID>, <PASSWORD> and <LAPI_URL> are required' . \PHP_EOL
         . 'Usage: php login.php <MACHINE_ID> <PASSWORD> <LAPI_URL> [<SCENARIOS_JSON>]' . \PHP_EOL
         . 'Example: php login.php my-machine-id my-password https://crowdsec:8080 \'["crowdsecurity/http-probing"]\''
         . \PHP_EOL);
}

$scenarios = json_decode($scenariosJson, true);
if (is_null($scenarios)) {
    exit('Param <SCENARIOS_JSON> is not a valid json' . \PHP_EOL
         . 'Usage: php login.php <MACHINE_ID> <PASSWORD> <LAPI_URL> [<SCENARIOS_JSON>]'
         . \PHP_EOL);
}

echo \PHP_EOL . 'Setting up cache ...' . \PHP_EOL;
$cacheDir = sys_get_temp_dir() . '/crowdsec-lapi-client-cache';
$cache = new FilesystemAdapter('crowdsec', 0, $cacheDir);
echo 'Cache directory: ' . $cacheDir . \PHP_EOL;

echo \PHP_EOL . 'Instantiate watcher client ...' . \PHP_EOL;
$configs = [
    'auth_type' => 'api_key',
    'api_url' => $lapiUrl,
    'machine_id' => $machineId,
    'password' => $password,
];
$logger = new ConsoleLog();
$client = new WatcherClient($configs, $cache, $scenarios, null, $logger);
echo 'Watcher client instantiated' . \PHP_EOL;

echo 'Calling ' . $client->getConfig('api_url') . ' for login ...' . \PHP_EOL;
echo 'Scenarios: ' . json_encode($scenarios) . \PHP_EOL;

try {
    $response = $client->login($scenarios);
    echo \PHP_EOL . 'Login response is:' . json_encode($response) . \PHP_EOL;
    echo \PHP_EOL . 'Token: ' . ($response['token'] ?? 'N/A') . \PHP_EOL;
    echo 'Expires: ' . ($response['expire'] ?? 'N/A') . \PHP_EOL;
} catch (\Exception $e) {
    echo \PHP_EOL . 'Login failed: ' . $e->getMessage() . \PHP_EOL;
    exit(1);
}