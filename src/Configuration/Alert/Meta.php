<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient\Configuration\Alert;

use CrowdSec\Common\Configuration\AbstractConfiguration;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;

class Meta extends AbstractConfiguration
{
    /** @var string[] The list of each configuration tree key */
    protected $keys = [
        'key',
        'value',
    ];

    #[\Override]
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('meta');
        $root = $treeBuilder->getRootNode();

        // @formatter:off
        $root
            ->children()
                ->scalarNode('key')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('value')->isRequired()->cannotBeEmpty()->end()
            ->end();
        // @formatter:on

        return $treeBuilder;
    }
}
