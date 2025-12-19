<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\Configuration;

use CrowdSec\LapiClient\Configuration;
use CrowdSec\LapiClient\Constants;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;

/**
 * The Watcher client configuration.
 *
 * Extends the base Configuration to add watcher-specific settings (machine_id, password).
 *
 * @author    CrowdSec team
 *
 * @see      https://crowdsec.net CrowdSec Official Website
 *
 * @copyright Copyright (c) 2022+ CrowdSec
 * @license   MIT License
 *
 * @psalm-type TWatcherConfig = array{
 *     user_agent_suffix: string,
 *     user_agent_version: string,
 *     api_url?: string,
 *     appsec_url?: string,
 *     auth_type?: string,
 *     api_key?: string,
 *     tls_cert_path?: string,
 *     tls_key_path?: string,
 *     tls_ca_cert_path?: string,
 *     tls_verify_peer?: bool,
 *     api_timeout?: int,
 *     api_connect_timeout?: int,
 *     appsec_timeout_ms?: int,
 *     appsec_connect_timeout_ms?: int,
 *     machine_id?: non-empty-string,
 *     password?: non-empty-string
 * }
 */
class Watcher extends Configuration
{
    /** @var string[] The list of each configuration tree key */
    protected $keys = [
        'user_agent_suffix',
        'user_agent_version',
        'api_url',
        'appsec_url',
        'auth_type',
        'api_key',
        'tls_cert_path',
        'tls_key_path',
        'tls_ca_cert_path',
        'tls_verify_peer',
        'api_timeout',
        'api_connect_timeout',
        'appsec_timeout_ms',
        'appsec_connect_timeout_ms',
        'machine_id',
        'password',
    ];

    /**
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     */
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = parent::getConfigTreeBuilder();
        /** @var ArrayNodeDefinition $rootNode */
        $rootNode = $treeBuilder->getRootNode();

        $this->addWatcherNodes($rootNode);

        return $treeBuilder;
    }

    /**
     * Override API key validation for Watcher.
     *
     * For Watcher, api_key auth requires machine_id and password instead of api_key.
     *
     * @param NodeDefinition|ArrayNodeDefinition $rootNode
     *
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     */
    protected function validateApiKey($rootNode): void
    {
        $rootNode
            ->validate()
            ->ifTrue(function (array $v) {
                if (Constants::AUTH_KEY === $v['auth_type']) {
                    return empty($v['machine_id']) || empty($v['password']);
                }

                return false;
            })
            ->thenInvalid('machine_id and password are required when auth_type is api_key')
            ->end();
    }

    /**
     * Watcher-specific settings.
     *
     * @param ArrayNodeDefinition $rootNode
     *
     * @throws \InvalidArgumentException
     */
    private function addWatcherNodes(ArrayNodeDefinition $rootNode): void
    {
        $rootNode->children()
            ->scalarNode('machine_id')->end()
            ->scalarNode('password')->end()
            ->end();
    }
}
