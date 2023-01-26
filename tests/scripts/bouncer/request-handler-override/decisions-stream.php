<?php

require_once __DIR__ . '/../../../../vendor/autoload.php';

use CrowdSec\LapiClient\Bouncer;
use CrowdSec\LapiClient\Constants;
use CrowdSec\Common\Client\RequestHandler\FileGetContents;

$startup = isset($argv[1]) ? (bool) $argv[1] : false;
$filter = isset($argv[2]) ? json_decode($argv[2], true)
    : ['scopes' => Constants::SCOPE_IP . ',' . Constants::SCOPE_RANGE];
$bouncerKey = $argv[3] ?? false;
$lapiUrl = $argv[4] ?? false;
if (!$bouncerKey || !$lapiUrl) {
    exit('Params <BOUNCER_KEY> and <LAPI_URL> are required' . \PHP_EOL
         . 'Usage: php decisions-stream.php <STARTUP> <FILTER_JSON> <BOUNCER_KEY> <LAPI_URL>'
         . \PHP_EOL);
}

if (is_null($filter)) {
    exit('Param <FILTER_JSON> is not a valid json' . \PHP_EOL
         . 'Usage: php decisions-stream.php <STARTUP> <FILTER_JSON> <BOUNCER_KEY> <LAPI_URL>'
         . \PHP_EOL);
}

echo \PHP_EOL . 'Instantiate bouncer ...' . \PHP_EOL;
// Config to use an Api Key for connection
$apiKeyConfigs = [
    'auth_type' => 'api_key',
    'api_url' => $lapiUrl,
    'api_key' => $bouncerKey,
];
echo \PHP_EOL . 'Instantiate custom request handler ...' . \PHP_EOL;
$customRequestHandler = new FileGetContents();
$client = new Bouncer($apiKeyConfigs, $customRequestHandler);
echo 'Bouncer instantiated' . \PHP_EOL;

echo 'Calling ' . $client->getConfig('api_url') . ' for decisions stream ...' . \PHP_EOL;
$response = $client->getStreamDecisions($startup, $filter);
echo 'Decisions stream response is:' . json_encode($response) . \PHP_EOL;
