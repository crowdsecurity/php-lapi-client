<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient;

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * The Watcher configuration.
 *
 * @author    CrowdSec team
 *
 * @see      https://crowdsec.net CrowdSec Official Website
 *
 * @copyright Copyright (c) 2022+ CrowdSec
 * @license   MIT License
 */
class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('config');
        /** @var ArrayNodeDefinition $rootNode */
        $rootNode = $treeBuilder->getRootNode();
        $rootNode->children()
            ->scalarNode('user_agent_suffix')
                ->validate()
                ->ifTrue(function (string $value) {
                    if (!empty($value)) {
                        return strlen($value) > 16 || 1 !== preg_match('#^[A-Za-z0-9]+$#', $value);
                    }

                    return false;
                })
                ->thenInvalid('Invalid user agent suffix. Length must be <= 16. Allowed chars are A-Za-z0-9')
                ->end()
            ->end()
        ->end()
        ;
        $this->validate($rootNode);
        $this->addConnectionNodes($rootNode);

        return $treeBuilder;
    }

    /**
     * LAPI connection settings.
     *
     * @param NodeDefinition|ArrayNodeDefinition $rootNode
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function addConnectionNodes($rootNode)
    {
        $rootNode->children()
            ->scalarNode('api_url')->defaultValue(Constants::DEFAULT_LAPI_URL)->end()
            ->enumNode('auth_type')
                ->values(
                    [
                        Constants::AUTH_KEY,
                        Constants::AUTH_TLS,
                    ]
                )
                ->defaultValue(Constants::AUTH_KEY)
            ->end()
            ->scalarNode('api_key')->end()
            ->scalarNode('tls_cert_path')
                ->info('Absolute path to the Bouncer certificate')->defaultValue('')
            ->end()
            ->scalarNode('tls_key_path')
                ->info('Absolute path to the Bouncer key')->defaultValue('')
            ->end()
            ->scalarNode('tls_ca_cert_path')
                ->info('Absolute path to the CA used to process TLS handshake')->defaultValue('')
            ->end()
            ->booleanNode('tls_verify_peer')->defaultValue(false)->end()
            ->integerNode('api_timeout')->min(1)->defaultValue(Constants::API_TIMEOUT)->end()
        ->end();
    }

    /**
     * Conditional validation.
     *
     * @param NodeDefinition|ArrayNodeDefinition $rootNode
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \RuntimeException
     */
    private function validate($rootNode)
    {
        $rootNode->validate()
            ->ifTrue(function (array $v) {
                if (Constants::AUTH_KEY === $v['auth_type'] && empty($v['api_key'])) {
                    return true;
                }

                return false;
            })
            ->thenInvalid('Api key is required as auth type is api_key')
            ->end()
            ->validate()
            ->ifTrue(function (array $v) {
                if (Constants::AUTH_TLS === $v['auth_type']) {
                    return empty($v['tls_cert_path']) || empty($v['tls_key_path']);
                }

                return false;
            })
            ->thenInvalid('Bouncer certificate and key paths are required for tls authentification.')
            ->end()
            ->validate()
            ->ifTrue(function (array $v) {
                if (Constants::AUTH_TLS === $v['auth_type'] && true === $v['tls_verify_peer']) {
                    return empty($v['tls_ca_cert_path']);
                }

                return false;
            })
            ->thenInvalid('CA path is required for tls authentification with verify_peer.')
            ->end();
    }
}
