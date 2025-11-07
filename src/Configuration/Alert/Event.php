<?php

namespace CrowdSec\LapiClient\Configuration\Alert;

use CrowdSec\Common\Configuration\AbstractConfiguration;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;

class Event extends AbstractConfiguration
{
    /** @var list<string> The list of each configuration tree key */
    protected $keys = [
        'meta',
        'timestamp',
    ];

    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('event');
        $rootNode = $treeBuilder->getRootNode();

        // @formatter:off
        $rootNode
            ->children()
                ->arrayNode('meta')->isRequired()
                    ->arrayPrototype()
                        ->children()
                            ->stringNode('key')->isRequired()->cannotBeEmpty()->end()
                            ->stringNode('value')->isRequired()->cannotBeEmpty()->end()
                        ->end()
                    ->end()
                ->end()
                ->scalarNode('timestamp')->isRequired()->cannotBeEmpty()->end()
            ->end()
        ;
        // @formatter:on

        return $treeBuilder;
    }
}
