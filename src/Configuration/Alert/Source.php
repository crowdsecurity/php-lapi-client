<?php

namespace CrowdSec\LapiClient\Configuration\Alert;

use CrowdSec\Common\Configuration\AbstractConfiguration;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;

class Source extends AbstractConfiguration
{
    /** @var list<string> The list of each configuration tree key */
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

    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('source');
        $rootNode = $treeBuilder->getRootNode();

        // @formatter:off
        $rootNode
            ->children()
                ->stringNode('scope')->isRequired()->cannotBeEmpty()->end()
                ->stringNode('value')->isRequired()->cannotBeEmpty()->end()
                ->stringNode('ip')->cannotBeEmpty()->end()
                ->stringNode('range')->cannotBeEmpty()->end()
                ->scalarNode('as_number')->cannotBeEmpty()->end()
                ->stringNode('as_name')->cannotBeEmpty()->end()
                ->stringNode('cn')->cannotBeEmpty()->end()
                ->floatNode('latitude')->min(-90)->max(90)->end()
                ->floatNode('longitude')->min(-180)->max(180)->end()
            ->end()
        ;
        // @formatter:on

        return $treeBuilder;
    }
}
