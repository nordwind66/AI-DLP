use crate::types::*;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Per-request context handed to every detector. Detectors must not retain it.
#[derive(Debug, Clone)]
pub struct DetectContext {
    pub direction: Direction,
    /// BCP-47-ish language hint ("zh", "en", "auto").
    pub language: String,
    /// Entity type whitelist requested by the caller (empty = all enabled by policy).
    pub entities: Vec<String>,
    /// Minimum confidence the policy cares about; detectors may use it to prune early.
    pub min_confidence: f32,
    /// Absolute deadline for the whole request.
    pub deadline: Option<Instant>,
    /// Opaque id for correlating logs. Never derived from content.
    pub request_id: String,
    /// Skip prefilters that depend on text outside the scanned buffer (gitleaks keyword gating).
    /// Used by window-mode stream scanning, where the result must be a superset of the full-text result.
    pub exhaustive: bool,
}

impl Default for DetectContext {
    fn default() -> Self {
        DetectContext {
            direction: Direction::Request,
            language: "auto".into(),
            entities: vec![],
            min_confidence: 0.0,
            deadline: None,
            request_id: String::new(),
            exhaustive: false,
        }
    }
}

/// Extensible detector interface.
///
/// Lifecycle: construction/loading (rules or model) happens in the concrete type's
/// constructor or `reload`; `shutdown` releases resources. Implementations must be
/// thread-safe: `detect` is called concurrently.
pub trait Detector: Send + Sync {
    fn name(&self) -> &str;
    /// Evidence class of the findings this detector produces (used by the merger).
    fn detect(&self, ctx: &DetectContext, text: &str) -> DlpResult<Vec<Entity>>;
    /// Batch detection. The default loops; NLP detectors override to batch the IPC.
    fn detect_batch(&self, ctx: &DetectContext, texts: &[&str]) -> Vec<DlpResult<Vec<Entity>>> {
        texts.iter().map(|t| self.detect(ctx, t)).collect()
    }
    fn status(&self) -> DetectorStatus;
    fn metrics(&self) -> DetectorMetrics;
    fn shutdown(&self) {}
    /// Allows the engine to recognise detector families that can share one IPC round trip.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Lock-light metrics helper for detector implementations.
#[derive(Default)]
pub struct MetricsRecorder {
    calls: AtomicU64,
    errors: AtomicU64,
    total_us: AtomicU64,
    max_us: AtomicU64,
    entities: AtomicU64,
    last_error: Mutex<String>,
}

impl MetricsRecorder {
    pub fn record(&self, started: Instant, result: &DlpResult<Vec<Entity>>) {
        let us = started.elapsed().as_micros() as u64;
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.total_us.fetch_add(us, Ordering::Relaxed);
        self.max_us.fetch_max(us, Ordering::Relaxed);
        match result {
            Ok(v) => {
                self.entities.fetch_add(v.len() as u64, Ordering::Relaxed);
            }
            Err(e) => {
                self.errors.fetch_add(1, Ordering::Relaxed);
                *self.last_error.lock() = e.to_string();
            }
        }
    }
    pub fn snapshot(&self) -> DetectorMetrics {
        DetectorMetrics {
            calls: self.calls.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            total_us: self.total_us.load(Ordering::Relaxed),
            max_us: self.max_us.load(Ordering::Relaxed),
            entities: self.entities.load(Ordering::Relaxed),
        }
    }
    pub fn last_error(&self) -> String {
        self.last_error.lock().clone()
    }
}
