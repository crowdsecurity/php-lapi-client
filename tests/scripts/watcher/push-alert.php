<?php

require_once __DIR__ . '/../../../vendor/autoload.php';

use CrowdSec\Common\Logger\ConsoleLog;
use CrowdSec\LapiClient\WatcherClient;
use Symfony\Component\Cache\Adapter\FilesystemAdapter;

$alertJson = $argv[1] ?? false;
$machineId = $argv[2] ?? false;
$password = $argv[3] ?? false;
$lapiUrl = $argv[4] ?? false;

if (!$alertJson || !$machineId || !$password || !$lapiUrl) {
    exit('Params <ALERT_JSON>, <MACHINE_ID>, <PASSWORD> and <LAPI_URL> are required' . \PHP_EOL
         . 'Usage: php push-alert.php <ALERT_JSON> <MACHINE_ID> <PASSWORD> <LAPI_URL>' . \PHP_EOL
         . 'Example: php push-alert.php \'{"scenario":"test/scenario","scenario_hash":"abc123","scenario_version":"1.0","message":"Test alert","events_count":1,"start_at":"2025-01-01T00:00:00Z","stop_at":"2025-01-01T00:00:01Z","capacity":10,"leakspeed":"10/1s","simulated":false,"remediation":true,"source":{"scope":"ip","value":"1.2.3.4"},"events":[]}\' my-machine-id my-password https://crowdsec:8080'
         . \PHP_EOL);
}

$alert = json_decode($alertJson, true);
if (is_null($alert)) {
    exit('Param <ALERT_JSON> is not a valid json' . \PHP_EOL
         . 'Usage: php push-alert.php <ALERT_JSON> <MACHINE_ID> <PASSWORD> <LAPI_URL>'
         . \PHP_EOL);
}

$logger = new ConsoleLog();

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
$client = new WatcherClient($configs, $cache, [], null, $logger);
echo 'Watcher client instantiated' . \PHP_EOL;

echo \PHP_EOL . 'Pushing alert to ' . $client->getConfig('api_url') . ' ...' . \PHP_EOL;
echo 'Alert: ' . json_encode($alert, \JSON_UNESCAPED_SLASHES) . \PHP_EOL;

try {
    $response = $client->pushAlerts([$alert]);
    echo \PHP_EOL . 'Push response (alert IDs):' . json_encode($response) . \PHP_EOL;
} catch (\Exception $e) {
    echo \PHP_EOL . 'Push failed: ' . $e->getMessage() . \PHP_EOL;
    exit(1);
}