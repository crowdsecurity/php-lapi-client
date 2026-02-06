<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\Configuration\Alert;

use CrowdSec\Common\Configuration\AbstractConfiguration;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;

class Source extends AbstractConfiguration
{
    /** @var string[] The list of each configuration tree key */
    protected $keys = [
        'scope',
        'value',
        'ip',
        'range',
        'as_number',
        'as_name',
        'cn',
        'latitude',
        'longitude',
    ];

    #[\Override]
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('source');
        $rootNode = $treeBuilder->getRootNode();

        // @formatter:off
        $rootNode
            ->children()
                ->scalarNode('scope')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('value')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('ip')->cannotBeEmpty()->end()
                ->scalarNode('range')->cannotBeEmpty()->end()
                ->scalarNode('as_number')->cannotBeEmpty()->end()
                ->scalarNode('as_name')->cannotBeEmpty()->end()
                ->scalarNode('cn')->cannotBeEmpty()->end()
                ->floatNode('latitude')->min(-90)->max(90)->end()
                ->floatNode('longitude')->min(-180)->max(180)->end()
            ->end()
        ;
        // @formatter:on

        return $treeBuilder;
    }
}
