<?php

declare(strict_types=1);

namespace CrowdSec\LapiClient;

use CrowdSec\LapiClient\Configuration\Metrics as PropertiesConfig;
use CrowdSec\LapiClient\Configuration\Metrics\Items as ItemsConfig;
use CrowdSec\LapiClient\Configuration\Metrics\Meta as MetaConfig;
use Symfony\Component\Config\Definition\Processor;

/**
 * The Metrics class.
 *
 * @author    CrowdSec team
 *
 * @see     https://crowdsec.net CrowdSec Official Website
 * @see     https://docs.crowdsec.net/docs/next/observability/usage_metrics/
 * @see     https://crowdsecurity.github.io/api_doc/index.html?urls.primaryName=LAPI#/Remediation%20component/usage-metrics
 *
 * @copyright Copyright (c) 2024+ CrowdSec
 * @license   MIT License
 *
 * @psalm-type TOS = array{
 *     name: string,
 *     version: string
 * }
 *
 * @psalm-type TMetric = array{
 *     name: string,
 *     type?: string,
 *     last_pull?: positive-int,
 *     version: string,
 *     os?: TOS,
 *     feature_flags?: array,
 *     utc_startup_timestamp: int
 * }
 *
 * @psalm-type TLabel = array{
 *     key: non-empty-string,
 *     value: string
 * }
 *
 * @psalm-type TItem = array{
 *     name: string,
 *     value: non-negative-int,
 *     unit: mixed,
 *     labels: list<TLabel>
 * }
 *
 * @psalm-type TMeta = array{
 *     window_size_seconds: int,
 *     utc_now_timestamp: positive-int
 * }
 *
 * @psalm-type TRemediationComponents = array{
 *     name: string,
 *     type?: string,
 *     last_pull?: positive-int,
 *     version: string,
 *     os?: TOS,
 *     feature_flags?: array,
 *     utc_startup_timestamp: int,
 *     metrics: list{
 *         0: array{
 *             meta: TMeta,
 *             items: list<TItem>
 *         }
 *     }
 * }
 */
class Metrics
{
    /**
     * @var list<TItem>
     */
    private $items;
    /**
     * @var TMeta
     */
    private $meta;
    /**
     * @var TMetric
     */
    private $properties;

    /**
     * @param TMetric $properties
     * @param TMeta $meta
     * @param list<TItem> $items
     */
    public function __construct(
        array $properties,
        array $meta,
        array $items = [],
    ) {
        $this->configureProperties($properties);
        $this->configureMeta($meta);
        $this->configureItems($items);
    }

    /**
     * @return array{
     *     remediation_components: list{0: TRemediationComponents}
     * }
     */
    public function toArray(): array
    {
        return [
            'remediation_components' => [
                $this->properties +
                [
                    'metrics' => [
                        [
                            'meta' => $this->meta,
                            'items' => $this->items,
                        ],
                    ],
                ],
            ],
        ];
    }

    private function configureItems(array $items): void
    {
        $configuration = new ItemsConfig();
        $processor = new Processor();
        $this->items = $processor->processConfiguration($configuration, [$configuration->cleanConfigs($items)]);
    }

    private function configureMeta(array $meta): void
    {
        $configuration = new MetaConfig();
        $processor = new Processor();
        $this->meta = $processor->processConfiguration($configuration, [$configuration->cleanConfigs($meta)]);
    }

    private function configureProperties(array $properties): void
    {
        $configuration = new PropertiesConfig();
        $processor = new Processor();
        $this->properties = $processor->processConfiguration(
            $configuration,
            [$configuration->cleanConfigs($properties)]
        );
    }
}
