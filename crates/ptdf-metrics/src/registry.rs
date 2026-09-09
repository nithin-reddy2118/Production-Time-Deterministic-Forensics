//! `Registry` — owns every named metric for a process and renders them in
//! Prometheus text exposition format (the format `/metrics` per
//! architecture §25 must serve). One `Registry` per process, shared via
//! `Arc` by whatever HTTP handler serves `/metrics` (the networking crate,
//! Module 8, owns that handler; this crate only owns the data model and
//! the text rendering, so it has no HTTP dependency at all).
//!
//! Scope: unlabeled metrics only for v1. Every metric this platform's own
//! components need for the §25 dogfooding note (agent overhead %,
//! ingestion throughput/backpressure, storage segment counts, replay
//! divergence rate) is a single time series, not a per-label family, so
//! label support is a real future extension, not something v1 is missing
//! for its stated purpose.

use crate::primitives::{Counter, Gauge};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, RwLock};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MetricsError {
    #[error("metric name '{0}' is already registered with a different type")]
    TypeConflict(String),

    #[error("invalid metric name '{0}': must match [a-zA-Z_:][a-zA-Z0-9_:]*")]
    InvalidName(String),
}

fn validate_name(name: &str) -> Result<(), MetricsError> {
    let mut chars = name.chars();
    let valid_first =
        matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_' || c == ':');
    let valid_rest = chars
        .clone()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':');
    if !name.is_empty() && valid_first && valid_rest {
        Ok(())
    } else {
        Err(MetricsError::InvalidName(name.to_string()))
    }
}

enum Metric {
    Counter(Arc<Counter>, &'static str),
    Gauge(Arc<Gauge>, &'static str),
}

#[derive(Default)]
pub struct Registry {
    metrics: RwLock<HashMap<String, Metric>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.metrics.read().map(|m| m.len()).unwrap_or(0);
        f.debug_struct("Registry")
            .field("metric_count", &count)
            .finish()
    }
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or fetch, if already registered under the same type) a
    /// counter named `name` with the given `help` text.
    pub fn counter(&self, name: &str, help: &'static str) -> Result<Arc<Counter>, MetricsError> {
        validate_name(name)?;
        let mut metrics = self.metrics.write().expect("Registry lock poisoned");
        match metrics.get(name) {
            Some(Metric::Counter(c, _)) => Ok(Arc::clone(c)),
            Some(Metric::Gauge(..)) => Err(MetricsError::TypeConflict(name.to_string())),
            None => {
                let c = Arc::new(Counter::new());
                metrics.insert(name.to_string(), Metric::Counter(Arc::clone(&c), help));
                Ok(c)
            }
        }
    }

    /// Register (or fetch) a gauge named `name`.
    pub fn gauge(&self, name: &str, help: &'static str) -> Result<Arc<Gauge>, MetricsError> {
        validate_name(name)?;
        let mut metrics = self.metrics.write().expect("Registry lock poisoned");
        match metrics.get(name) {
            Some(Metric::Gauge(g, _)) => Ok(Arc::clone(g)),
            Some(Metric::Counter(..)) => Err(MetricsError::TypeConflict(name.to_string())),
            None => {
                let g = Arc::new(Gauge::new());
                metrics.insert(name.to_string(), Metric::Gauge(Arc::clone(&g), help));
                Ok(g)
            }
        }
    }

    /// Render every registered metric in Prometheus text exposition
    /// format, in a stable (sorted by name) order for deterministic,
    /// diffable output.
    pub fn render(&self) -> String {
        let metrics = self.metrics.read().expect("Registry lock poisoned");
        let mut names: Vec<&String> = metrics.keys().collect();
        names.sort();

        let mut out = String::new();
        for name in names {
            match &metrics[name] {
                Metric::Counter(c, help) => {
                    let _ = writeln!(out, "# HELP {name} {help}");
                    let _ = writeln!(out, "# TYPE {name} counter");
                    let _ = writeln!(out, "{name} {}", c.get());
                }
                Metric::Gauge(g, help) => {
                    let _ = writeln!(out, "# HELP {name} {help}");
                    let _ = writeln!(out, "# TYPE {name} gauge");
                    let _ = writeln!(out, "{name} {}", g.get());
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_render_a_counter() {
        let registry = Registry::new();
        let c = registry
            .counter("ptdf_events_recorded_total", "Total events recorded")
            .unwrap();
        c.inc_by(42);

        let rendered = registry.render();
        assert!(rendered.contains("# HELP ptdf_events_recorded_total Total events recorded"));
        assert!(rendered.contains("# TYPE ptdf_events_recorded_total counter"));
        assert!(rendered.contains("ptdf_events_recorded_total 42"));
    }

    #[test]
    fn register_and_render_a_gauge() {
        let registry = Registry::new();
        let g = registry
            .gauge("ptdf_sink_queue_depth", "Current sink queue depth")
            .unwrap();
        g.set(17);

        let rendered = registry.render();
        assert!(rendered.contains("# TYPE ptdf_sink_queue_depth gauge"));
        assert!(rendered.contains("ptdf_sink_queue_depth 17"));
    }

    #[test]
    fn registering_the_same_name_twice_returns_the_same_metric() {
        let registry = Registry::new();
        let c1 = registry.counter("ptdf_x", "help").unwrap();
        let c2 = registry.counter("ptdf_x", "help").unwrap();
        c1.inc();
        assert_eq!(
            c2.get(),
            1,
            "both handles must refer to the same underlying counter"
        );
    }

    #[test]
    fn registering_a_name_under_a_conflicting_type_is_rejected() {
        let registry = Registry::new();
        registry.counter("ptdf_y", "help").unwrap();
        let err = registry.gauge("ptdf_y", "help").unwrap_err();
        assert_eq!(err, MetricsError::TypeConflict("ptdf_y".to_string()));
    }

    #[test]
    fn invalid_metric_names_are_rejected() {
        let registry = Registry::new();
        assert!(registry.counter("has a space", "help").is_err());
        assert!(registry.counter("9starts_with_digit", "help").is_err());
        assert!(registry.counter("", "help").is_err());
        assert!(registry.counter("valid_name:with_colon", "help").is_ok());
    }

    #[test]
    fn render_output_is_sorted_by_metric_name() {
        let registry = Registry::new();
        registry.counter("ptdf_zzz", "help").unwrap();
        registry.counter("ptdf_aaa", "help").unwrap();

        let rendered = registry.render();
        let aaa_pos = rendered.find("ptdf_aaa").unwrap();
        let zzz_pos = rendered.find("ptdf_zzz").unwrap();
        assert!(
            aaa_pos < zzz_pos,
            "output must be sorted so it's diffable across scrapes"
        );
    }

    #[test]
    fn empty_registry_renders_empty_string() {
        let registry = Registry::new();
        assert_eq!(registry.render(), "");
    }
}
