<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\Tests;

/**
 * Mocked data for unit test.
 *
 * @author    CrowdSec team
 *
 * @see      https://crowdsec.net CrowdSec Official Website
 *
 * @copyright Copyright (c) 2022+ CrowdSec
 * @license   MIT License
 */
class MockedData
{
    public const HTTP_200 = 200;
    public const HTTP_400 = 400;
    public const HTTP_401 = 401;
    public const HTTP_403 = 403;
    public const HTTP_500 = 500;

    public const DECISIONS_STREAM_LIST = <<<EOT
{"new": [], "deleted": []}
EOT;

    public const DECISIONS_FILTER = <<<EOT
[{"duration":"3h59m56.205431304s","id":1,"origin":"cscli","scenario":"manual 'ban' from ''","scope":"Ip","type":"ban","value":"172.26.0.2"}]
EOT;

    public const UNAUTHORIZED = <<<EOT
{"message":"Unauthorized"}
EOT;

    public const APPSEC_ALLOWED = <<<EOT
{"action":"allow","http_status":200}
EOT;

    public const LOGIN_SUCCESS = <<<EOT
{"code":200,"expire":"2025-01-01T00:00:00Z","token":"test-jwt-token"}
EOT;

    public const ALERTS_PUSH_SUCCESS = <<<EOT
["1"]
EOT;

    public const ALERTS_SEARCH_SUCCESS = <<<EOT
[]
EOT;

    public const ALERTS_DELETE_SUCCESS = <<<EOT
{"nbDeleted":"1"}
EOT;

    public const ALERT_BY_ID_SUCCESS = <<<EOT
{"id":1,"capacity":10,"created_at":"2025-01-01T00:00:00Z","decisions":[],"events":[],"events_count":1,"labels":null,"leakspeed":"10/1s","machine_id":"test","message":"Test alert","meta":[],"scenario":"test/scenario","scenario_hash":"abc123","scenario_version":"1.0","simulated":false,"source":{"scope":"ip","value":"1.2.3.4"},"start_at":"2025-01-01T00:00:00Z","stop_at":"2025-01-01T00:00:01Z","uuid":"test-uuid"}
EOT;

    public const ALERT_NOT_FOUND = <<<EOT
{"message":"not found"}
EOT;
}
