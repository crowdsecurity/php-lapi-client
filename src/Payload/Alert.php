<?php

namespace CrowdSec\LapiClient\Payload;

use CrowdSec\Common\Configuration\AbstractConfiguration;
use CrowdSec\LapiClient\Configuration\Alert as AlertConf;
use CrowdSec\LapiClient\Configuration\Alert\Decision;
use CrowdSec\LapiClient\Configuration\Alert\Event;
use CrowdSec\LapiClient\Configuration\Alert\Meta;
use CrowdSec\LapiClient\Configuration\Alert\Source;
use Symfony\Component\Config\Definition\Processor;

/**
 * Only for validation purposes.
 *
 * @psalm-type TProps = array{
 *     scenario: string,
 *     scenario_hash: string,
 *     scenario_version: string,
 *     message: string,
 *     events_count: int,
 *     start_at: string,
 *     stop_at: string,
 *     capacity: int,
 *     leakspeed: string,
 *     simulated: bool,
 *     remediation: bool
 * }
 *
 * @psalm-type TSource = array{
 *     scope: string,
 *     value: string,
 *     ip?: string,
 *     range?: string,
 *     as_number?: string,
 *     as_name?: string,
 *     cn?: string,
 *     latitude?: float,
 *     longitude?: float
 * }
 *
 * @psalm-type TDecision = array{
 *     origin: string,
 *     type: string,
 *     scope: string,
 *     value: string,
 *     duration: string,
 *     until?: string,
 *     scenario: string
 * }
 *
 * @psalm-type TMeta = array{
 *     key: string,
 *     value: string
 * }
 *
 * @psalm-type TEvent = array{
 *     meta: list<TMeta>,
 *     timestamp: string
 * }
 *
 * @psalm-type TAlertFull = array{
 *     scenario: string,
 *     scenario_hash: string,
 *     scenario_version: string,
 *     message: string,
 *     events_count: int,
 *     start_at: string,
 *     stop_at: string,
 *     capacity: int,
 *     leakspeed: string,
 *     simulated: bool,
 *     remediation: bool,
 *     source: TSource,
 *     events: list<TEvent>,
 *     decisions: list<TDecision>,
 *     meta: list<TMeta>,
 *     labels: list<non-empty-string>
 * }
 */
class Alert implements \JsonSerializable
{
    /**
     * @var list<TProps>
     */
    private $properties;

    /**
     * @var list<TEvent>
     */
    private $events;

    /**
     * @var list<TDecision>
     */
    private $decisions = [];

    /**
     * @var TSource
     */
    private $source;

    /**
     * @var list<TMeta>
     */
    private $meta = [];

    /**
     * @var list<string>
     */
    private $labels = [];

    /**
     * @param TProps $properties
     * @param TSource $source
     * @param list<TEvent> $events
     * @param list<TDecision> $decisions
     * @param list<TMeta> $meta
     * @param list<string> $labels
     */
    public function __construct(
        array $properties,
        array $source,
        array $events = [],
        array $decisions = [],
        array $meta = [],
        array $labels = []
    ) {
        $processor = new Processor();
        $this->configureProperties($processor, $properties);
        $this->configureSource($processor, $source);
        $this->configureDecisions($processor, $decisions);
        $this->configureEvents($processor, $events);
        $this->configureMetaList($processor, $meta);
        $this->labels = \array_filter($labels);
    }

    /**
     * @param TAlertFull $data
     * @return void
     */
    public static function fromArray(array $data): self
    {
        return new self(
            $data,
            $data['source'] ?? [],
            $data['events'] ?? [],
            $data['decisions'] ?? [],
            $data['meta'] ?? [],
            $data['labels'] ?? []
        );
    }

    /**
     * @return TAlertFull
     */
    public function toArray(): array
    {
        $result = $this->properties;
        if ([] !== $this->decisions) {
            $result['decisions'] = $this->decisions;
        }
        if ([] !== $this->events) {
            $result['events'] = $this->events;
        }
        if (null !== $this->source) {
            $result['source'] = $this->source;
        }
        if ([] !== $this->meta) {
            $result['meta'] = $this->meta;
        }
        if ([] !== $this->labels) {
            $result['labels'] = $this->labels;
        }
        return $result;
    }

    private function configureProperties(Processor $processor, array $properties): void
    {
        $configuration = new AlertConf();
        $this->properties = $processor->processConfiguration(
            $configuration,
            [$configuration->cleanConfigs($properties)]
        );
    }

    /**
     * @param ?TSource $source
     */
    private function configureSource(Processor $processor, ?array $source): void
    {
        if (null === $source) {
            return;
        }

        $configuration = new Source();
        $this->source = $processor->processConfiguration($configuration, [$configuration->cleanConfigs($source)]);
    }

    /**
     * @param list<TDecision> $list
     */
    private function configureDecisions(Processor $processor, array $list): void
    {
        $this->decisions = $this->handleList($processor, new Decision(), $list);
    }

    /**
     * @param list<TEvent> $list
     */
    private function configureEvents(Processor $processor, array $list): void
    {
        $this->events = $this->handleList($processor, new Event(), $list);
    }

    /**
     * @param list<TMeta> $list
     */
    private function configureMetaList(Processor $processor, array $list): void
    {
        $this->meta = $this->handleList($processor, new Meta(), $list);
    }

    private function handleList(Processor $processor, AbstractConfiguration $param, array $list): array
    {
        $result = [];
        foreach ($list as $item) {
            $result[] = $processor->processConfiguration($param, [$param->cleanConfigs($item)]);
        }
        return $result;
    }

    public function jsonSerialize(): mixed
    {
        return $this->toArray();
    }
}
