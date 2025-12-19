<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\Configuration\Alert;

use CrowdSec\Common\Configuration\AbstractConfiguration;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;

class Decision extends AbstractConfiguration
{
    /** @var string[] The list of each configuration tree key */
    protected $keys = [
        'origin',
        'type',
        'scope',
        'value',
        'duration',
        'until',
        'scenario',
    ];

    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('decision');
        $rootNode = $treeBuilder->getRootNode();

        // @formatter:off
        $rootNode
            ->children()
                ->scalarNode('origin')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('type')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('scope')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('value')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('duration')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('until')->cannotBeEmpty()->end()
                ->scalarNode('scenario')->isRequired()->cannotBeEmpty()->end()
            ->end()
        ;
        // @formatter:on

        return $treeBuilder;
    }
}
