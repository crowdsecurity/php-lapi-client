<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient;

/**
 * @psalm-import-type TAlertFull from \CrowdSec\LapiClient\Payload\Alert
 */
interface AlertPusherInterface
{
    /**
     * Push alerts to LAPI.
     *
     * @param list<TAlertFull> $alerts
     *
     * @return list<string>
     *
     * @throws ClientException
     */
    public function pushAlerts(array $alerts): array;
}
