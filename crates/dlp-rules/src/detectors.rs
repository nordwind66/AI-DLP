//! `Detector` implementations backed by a hot-swappable [`RuleSet`].
//!
//! * `RegexDetector`      – PII/contact/financial/internal pattern rules, portable `regex` engine.
//! * `HyperscanDetector`  – same rules, Hyperscan prefilter + exact regex confirmation.
//! * `SecretDetector`     – gitleaks-semantics credential rules (keywords, entropy, allowlists...).
//! * `DictionaryDetector` – company / project / system names and custom confidential terms.
//!
//! All four read the current rule set through an `ArcSwap`, so `reload_rules()` swaps the set
//! atomically and in-flight scans keep using the `Arc` they already loaded.
use crate::ruleset::{RuleGroup, RuleSet, ScanOptions};
use arc_swap::ArcSwap;
use dlp_core::*;
use std::sync::Arc;
use std::time::Instant;

pub type RuleSetHandle = Arc<ArcSwap<RuleSet>>;

pub fn new_handle(rs: RuleSet) -> RuleSetHandle {
    Arc::new(ArcSwap::from_pointee(rs))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Regex,
    Hyperscan,
    Secret,
    Dictionary,
}

pub struct RuleDetector {
    kind: Kind,
    handle: RuleSetHandle,
    metrics: MetricsRecorder,
    honor_inline_allow: bool,
}

pub type RegexDetector = RuleDetector;
pub type HyperscanDetector = RuleDetector;
pub type SecretDetector = RuleDetector;
pub type DictionaryDetector = RuleDetector;

impl RuleDetector {
    pub fn regex(handle: RuleSetHandle) -> Self {
        Self::mk(Kind::Regex, handle)
    }
    pub fn hyperscan(handle: RuleSetHandle) -> Self {
        Self::mk(Kind::Hyperscan, handle)
    }
    pub fn secret(handle: RuleSetHandle) -> Self {
        Self::mk(Kind::Secret, handle)
    }
    pub fn dictionary(handle: RuleSetHandle) -> Self {
        Self::mk(Kind::Dictionary, handle)
    }
    fn mk(kind: Kind, handle: RuleSetHandle) -> Self {
        RuleDetector { kind, handle, metrics: MetricsRecorder::default(), honor_inline_allow: false }
    }
    fn opts(&self, ctx: &DetectContext) -> ScanOptions {
        ScanOptions {
            use_hs: self.kind == Kind::Hyperscan || (self.kind == Kind::Secret),
            ignore_keywords: ctx.exhaustive,
            entity_filter: ctx.entities.clone(),
            deadline: ctx.deadline,
            honor_inline_allow: self.honor_inline_allow,
        }
    }
}

impl Detector for RuleDetector {
    fn name(&self) -> &str {
        match self.kind {
            Kind::Regex => "regex",
            Kind::Hyperscan => "hyperscan",
            Kind::Secret => "secret",
            Kind::Dictionary => "dictionary",
        }
    }

    fn detect(&self, ctx: &DetectContext, text: &str) -> DlpResult<Vec<Entity>> {
        let t0 = Instant::now();
        let rs = self.handle.load();
        let opts = self.opts(ctx);
        let mut ents = match self.kind {
            Kind::Regex | Kind::Hyperscan => rs.scan(text, RuleGroup::Pii, &opts),
            Kind::Secret => rs.scan(text, RuleGroup::Secret, &opts),
            Kind::Dictionary => rs.scan_dictionary(text, &opts),
        };
        for e in ents.iter_mut() {
            e.detector = self.name().to_string();
        }
        let res = Ok(ents);
        self.metrics.record(t0, &res);
        res
    }

    fn status(&self) -> DetectorStatus {
        let rs = self.handle.load();
        let (state, msg) = match self.kind {
            Kind::Hyperscan if !rs.hs_active() => (
                DetectorState::Unavailable,
                rs.report.hs_error.clone().unwrap_or_else(|| "Hyperscan not enabled for this rule set; regex engine used".into()),
            ),
            Kind::Hyperscan if !rs.report.hs_failed.is_empty() => (
                DetectorState::Degraded,
                format!("{} rule pattern(s) not accepted by Hyperscan; they run on the exact regex path", rs.report.hs_failed.len()),
            ),
            _ => (DetectorState::Ready, format!("{} rules, ruleset v{}", rs.rule_count(), rs.version)),
        };
        DetectorStatus { name: self.name().into(), state, message: msg, version: if rs.hs_active() { rs.report.hs_version.clone() } else { "regex-1".into() } }
    }

    fn metrics(&self) -> DetectorMetrics {
        self.metrics.snapshot()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
