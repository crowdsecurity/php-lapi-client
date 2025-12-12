<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\Storage;

use CrowdSec\LapiClient\WatcherClient;
use Psr\Cache\CacheItemPoolInterface;

final class TokenStorage implements TokenStorageInterface
{
    /**
     * @var WatcherClient
     */
    private $watcher;

    /**
     * @var CacheItemPoolInterface
     */
    private $cache;
    /**
     * @var array
     */
    private $scenarios;

    public function __construct(WatcherClient $watcher, CacheItemPoolInterface $cache, array $scenarios = [])
    {
        $this->watcher = $watcher;
        $this->cache = $cache;
        $this->scenarios = $scenarios;
    }

    public function retrieveToken(): ?string
    {
        $ci = $this->cache->getItem('crowdsec_token');
        if (!$ci->isHit()) {
            $tokenInfo = $this->watcher->login($this->scenarios);
            if (200 !== $tokenInfo['code']) {
                return null;
            }
            \assert(isset($tokenInfo['token']));
            $ci
                ->set($tokenInfo['token'])
                ->expiresAt(new \DateTime($tokenInfo['expire']));
            $this->cache->save($ci);
        }

        return $ci->get();
    }
}
