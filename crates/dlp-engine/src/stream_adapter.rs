//! Connects the generic stream scanner to the engine pipeline.
use crate::api::*;
use crate::engine::DlpEngine;
use dlp_core::*;
use dlp_stream::*;
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct StreamOptions {
    pub policy_id: Option<String>,
    pub session_id: Option<String>,
    /// reversible anonymization of the streamed text (rare for responses; default is sanitize)
    pub anonymize: bool,
    /// override the policy's stream_mode
    pub mode: Option<String>,
    pub max_buffer_bytes: Option<usize>,
    pub nonce_placeholders: Option<bool>,
}

pub struct EngineTextScanner {
    engine: Arc<DlpEngine>,
    caller: Caller,
    policy_id: String,
    anonymize: bool,
    session_id: Option<String>,
    nonce: Option<bool>,
    bound: Option<usize>,
    exhaustive: bool,
}

impl TextScanner for EngineTextScanner {
    fn scan(&mut self, text: &str, direction: Direction) -> Result<ScanOut, String> {
        let mut r = DetectRequest::new(text);
        r.direction = direction;
        r.policy_id = Some(self.policy_id.clone());
        r.mode = Some(if self.anonymize { Mode::Anonymize } else { Mode::Sanitize });
        r.session_id = self.session_id.clone();
        r.nonce_placeholders = self.nonce;
        r.exhaustive = self.exhaustive;
        let resp = self.engine.process(&self.caller, &r).map_err(|e| e.to_string())?;
        let mut out = ScanOut { degraded: resp.degraded, ..Default::default() };
        if resp.decision == Verdict::Blocked {
            out.blocked = Some(resp.blocked_reason.clone().unwrap_or_else(|| "blocked".into()));
        }
        for e in &resp.entities {
            if e.action.modifies() || e.action == Action::Block {
                out.actionable += 1;
            }
            *out.counts.entry(e.entity_type.clone()).or_insert(0) += 1;
            if let Some(rep) = &e.replacement {
                out.spans.push(Span { entity_type: e.entity_type.clone(), start: e.byte_start, end: e.byte_end, replacement: rep.clone() });
            }
        }
        out.spans.sort_by_key(|s| s.start);
        Ok(out)
    }
    fn window_bound(&self) -> Option<usize> {
        self.bound
    }
}

pub struct EngineStream {
    inner: StreamScanner<EngineTextScanner>,
    pub session_id: Option<String>,
}

impl EngineStream {
    pub fn push(&mut self, bytes: &[u8]) -> Vec<u8> {
        self.inner.push(bytes)
    }
    pub fn finish(&mut self) -> Vec<u8> {
        self.inner.finish()
    }
    pub fn stats(&self) -> &StreamStats {
        &self.inner.stats
    }
    pub fn is_blocked(&self) -> bool {
        self.inner.is_blocked()
    }
}

impl DlpEngine {
    pub fn open_stream(self: &Arc<Self>, caller: &Caller, opts: &StreamOptions) -> DlpResult<EngineStream> {
        let need = if opts.anonymize { "anonymize" } else { "sanitize" };
        if !caller.has_scope(need) {
            return Err(DlpError::Forbidden(format!("missing scope '{need}'")));
        }
        let pid = opts.policy_id.clone().unwrap_or_else(|| self.cfg.default_policy.clone());
        let policy = self.policy(&pid).ok_or_else(|| DlpError::NotFound(format!("policy '{pid}'")))?;
        let requested = match opts.mode.as_deref().unwrap_or(&policy.stream_mode) {
            "window" => RequestedMode::Window,
            _ => RequestedMode::Strict,
        };
        // the hold-back proof only covers deterministic rule detectors
        let rule_only = policy.enabled_detectors.iter().all(|d| matches!(d.as_str(), "regex" | "hyperscan" | "secret" | "dictionary"));
        let bound = if rule_only { self.ruleset().window_bound_all() } else { None };
        let session_id = if opts.anonymize {
            Some(opts.session_id.clone().unwrap_or_else(|| {
                use rand::RngCore;
                let mut b = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut b);
                hex::encode(b)
            }))
        } else {
            opts.session_id.clone()
        };
        let scanner = EngineTextScanner { engine: self.clone(), caller: caller.clone(), policy_id: pid, anonymize: opts.anonymize, session_id: session_id.clone(), nonce: opts.nonce_placeholders, bound, exhaustive: requested == RequestedMode::Window && bound.is_some() };
        let cfg = StreamConfig { requested, max_buffer_bytes: opts.max_buffer_bytes.unwrap_or(self.cfg.limits.max_text_bytes), max_event_bytes: 1 << 20, unmodifiable: match policy.unmodifiable_action.as_str() { "block" => UnmodAction::Block, "audit" => UnmodAction::Audit, _ => UnmodAction::Drop } };
        Ok(EngineStream { inner: StreamScanner::new(cfg, scanner), session_id })
    }
}
