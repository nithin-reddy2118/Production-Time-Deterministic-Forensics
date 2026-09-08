//! Lock-free (atomic-based) `Counter` and `Gauge` primitives.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

/// A monotonically non-decreasing counter (Prometheus `counter` type).
/// `inc`/`inc_by` are the only mutators — there is deliberately no `set` or
/// `dec`, matching the Prometheus counter contract (a counter that can go
/// down isn't a counter; use `Gauge` for that).
#[derive(Debug, Default)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_by(&self, delta: u64) {
        self.value.fetch_add(delta, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

/// A value that can go up or down (Prometheus `gauge` type).
#[derive(Debug, Default)]
pub struct Gauge {
    value: AtomicI64,
}

impl Gauge {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, v: i64) {
        self.value.store(v, Ordering::Relaxed);
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec(&self) {
        self.value.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn add(&self, delta: i64) {
        self.value.fetch_add(delta, Ordering::Relaxed);
    }

    pub fn get(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_starts_at_zero_and_increments() {
        let c = Counter::new();
        assert_eq!(c.get(), 0);
        c.inc();
        c.inc();
        c.inc_by(10);
        assert_eq!(c.get(), 12);
    }

    #[test]
    fn gauge_can_go_up_and_down() {
        let g = Gauge::new();
        g.set(5);
        assert_eq!(g.get(), 5);
        g.inc();
        assert_eq!(g.get(), 6);
        g.dec();
        g.dec();
        assert_eq!(g.get(), 4);
        g.add(-10);
        assert_eq!(g.get(), -6);
    }

    #[test]
    fn counter_is_safe_under_concurrent_increment() {
        use std::sync::Arc;
        use std::thread;

        let counter = Arc::new(Counter::new());
        let mut handles = Vec::new();
        for _ in 0..8 {
            let c = Arc::clone(&counter);
            handles.push(thread::spawn(move || {
                for _ in 0..1000 {
                    c.inc();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(counter.get(), 8000);
    }
}
