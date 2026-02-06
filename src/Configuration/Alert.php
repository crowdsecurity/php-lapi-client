<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\Configuration;

use CrowdSec\Common\Configuration\AbstractConfiguration;
use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;

class Alert extends AbstractConfiguration
{
    /** @var string[] The list of each configuration tree key */
    protected $keys = [
        'scenario',
        'scenario_hash',
        'scenario_version',
        'message',
        'events_count',
        'start_at',
        'stop_at',
        'capacity',
        'leakspeed',
        'simulated',
        'remediation',
    ];

    #[\Override]
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('alert');
        /** @var ArrayNodeDefinition $rootNode */
        $rootNode = $treeBuilder->getRootNode();
        // @formatter:off
        $rootNode
            ->children()
                ->scalarNode('scenario')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('scenario_hash')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('scenario_version')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('message')->isRequired()->cannotBeEmpty()->end()
                ->integerNode('events_count')->isRequired()->min(0)->end()
                ->scalarNode('start_at')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('stop_at')->isRequired()->cannotBeEmpty()->end()
                ->integerNode('capacity')->isRequired()->min(0)->end()
                ->scalarNode('leakspeed')->isRequired()->cannotBeEmpty()->end()
                ->booleanNode('simulated')->isRequired()->end()
                ->booleanNode('remediation')->isRequired()->end()
            ->end()
        ;
        // @formatter:on

        return $treeBuilder;
    }
}
