<?php

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
                ->stringNode('origin')->isRequired()->cannotBeEmpty()->end()
                ->stringNode('type')->isRequired()->cannotBeEmpty()->end()
                ->stringNode('scope')->isRequired()->cannotBeEmpty()->end()
                ->stringNode('value')->isRequired()->cannotBeEmpty()->end()
                ->stringNode('duration')->isRequired()->cannotBeEmpty()->end()
                ->stringNode('until')->cannotBeEmpty()->end()
                ->stringNode('scenario')->isRequired()->cannotBeEmpty()->end()
            ->end()
        ;
        // @formatter:on

        return $treeBuilder;
    }
}
