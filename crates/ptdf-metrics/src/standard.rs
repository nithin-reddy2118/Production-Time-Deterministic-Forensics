//! `StandardMetrics` — the concrete metric names architecture §25 calls
//! out by example ("agent overhead %, ingestion throughput/backpressure,
//! storage segment counts, replay divergence rate"), bundled into one
//! struct so every binary (agent, ingestion, replay, CLI) registers the
//! same names rather than each inventing its own — consistent naming is
//! what makes cross-component Grafana dashboards/alerts possible at all.

use crate::registry::{MetricsError, Registry};
use crate::{Counter, Gauge};
use std::sync::Arc;

#[derive(Debug)]
pub struct StandardMetrics {
    pub events_recorded_total: Arc<Counter>,
    pub events_shed_total: Arc<Counter>,
    pub sink_queue_depth: Arc<Gauge>,
    pub segments_sealed_total: Arc<Counter>,
    pub replay_events_served_total: Arc<Counter>,
    pub replay_divergences_total: Arc<Counter>,
}

impl StandardMetrics {
    pub fn register(registry: &Registry) -> Result<Self, MetricsError> {
        Ok(Self {
            events_recorded_total: registry.counter(
                "ptdf_events_recorded_total",
                "Total events successfully recorded by this process",
            )?,
            events_shed_total: registry.counter(
                "ptdf_events_shed_total",
                "Total non-load-bearing events shed under backpressure (see BoundedSink, architecture §8)",
            )?,
            sink_queue_depth: registry.gauge(
                "ptdf_sink_queue_depth",
                "Current number of events buffered in the local recorder sink",
            )?,
            segments_sealed_total: registry.counter(
                "ptdf_segments_sealed_total",
                "Total storage segments sealed by this process",
            )?,
            replay_events_served_total: registry.counter(
                "ptdf_replay_events_served_total",
                "Total recorded events successfully served during replay",
            )?,
            replay_divergences_total: registry.counter(
                "ptdf_replay_divergences_total",
                "Total divergences detected during replay (architecture §6 step 4)",
            )?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_metrics_register_without_conflict() {
        let registry = Registry::new();
        let metrics = StandardMetrics::register(&registry).unwrap();
        metrics.events_recorded_total.inc_by(5);
        metrics.sink_queue_depth.set(3);

        let rendered = registry.render();
        assert!(rendered.contains("ptdf_events_recorded_total 5"));
        assert!(rendered.contains("ptdf_sink_queue_depth 3"));
    }

    #[test]
    fn registering_standard_metrics_twice_on_the_same_registry_is_idempotent() {
        let registry = Registry::new();
        let m1 = StandardMetrics::register(&registry).unwrap();
        let m2 = StandardMetrics::register(&registry).unwrap();
        m1.events_recorded_total.inc();
        assert_eq!(m2.events_recorded_total.get(), 1);
    }
}
