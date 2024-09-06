<?php

require_once __DIR__ . '/../../../vendor/autoload.php';

use CrowdSec\Common\Logger\ConsoleLog;
use CrowdSec\LapiClient\Bouncer;

$apiKey = $argv[1] ?? false;
$headers = isset($argv[2]) ? json_decode($argv[2], true) : [];
$rawBody = $argv[5] ?? '';
$appSecMethod = $argv[3] ?? false;
$appSecUrl = $argv[4] ?? false;
if (!$apiKey || !$appSecMethod || !$appSecUrl) {
    exit('Params <BOUNCER_KEY> and </BOUNCER_KEY><APP_SEC_METHOD> and <APP_SEC_URL> are required' . \PHP_EOL
         . 'Usage: php appsec-decisions.php <BOUNCER_KEY> <HEADERS_JSON> <APP_SEC_METHOD> <APP_SEC_URL> [<RAW_BODY_STRING>]'
         . \PHP_EOL);
}

if (is_null($headers)) {
    exit('Param <HEADERS_JSON> is not a valid json' . \PHP_EOL
         . 'Usage: php appsec-decision.php <BOUNCER_KEY> <HEADERS_JSON> <APP_SEC_METHOD> <APP_SEC_URL> [<RAW_BODY_STRING>]'
         . \PHP_EOL);
}

echo \PHP_EOL . 'Instantiate bouncer ...' . \PHP_EOL;
// Config to use app_sec_url
$configs = [
    'app_sec_url' => $appSecUrl,
    'api_key' => $apiKey,
];
$logger = new ConsoleLog();
$client = new Bouncer($configs, null, $logger);
echo 'Bouncer instantiated' . \PHP_EOL;

$headers += ['X-Crowdsec-Appsec-Api-Key' => $apiKey];

echo 'Calling ' . $client->getConfig('app_sec_url') . ' ...' . \PHP_EOL;
echo 'Headers: ';
print_r(json_encode($headers));
$response = $client->getAppSecDecision($appSecMethod, $headers, $rawBody);
echo \PHP_EOL . 'Decision response is:' . json_encode($response) . \PHP_EOL;
