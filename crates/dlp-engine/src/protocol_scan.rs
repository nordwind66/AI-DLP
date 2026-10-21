//! Structured (JSON) scanning on top of the text pipeline.
use crate::api::*;
use crate::engine::DlpEngine;
use dlp_core::*;
use dlp_protocol::*;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ProtocolRequest {
    pub body: Value,
    pub protocol: Option<Protocol>,
    /// base direction for request-side content (bodies that are clearly responses override per field)
    pub direction: Direction,
    pub policy_id: Option<String>,
    pub session_id: Option<String>,
    pub mode: Mode,
    pub nonce_placeholders: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SlotFinding {
    pub pointer: String,
    pub kind: &'static str,
    pub direction: Direction,
    pub modifiable: bool,
    pub decision: Verdict,
    pub entities: Vec<EntityOut>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolResult {
    pub protocol: &'static str,
    pub decision: Verdict,
    pub blocked_reason: Option<String>,
    /// modified body (`None` in detect mode or when blocked: the caller must not forward the original)
    pub body: Option<Value>,
    pub slots_scanned: usize,
    pub unique_texts_processed: usize,
    pub slots_skipped: Vec<Skipped>,
    pub findings: Vec<SlotFinding>,
    /// sensitive data found in integrity-protected fields that cannot be edited (dropped, blocked or flagged per policy)
    pub unmodifiable_findings: Vec<String>,
    pub degraded: bool,
    pub warnings: Vec<String>,
    pub detector_status: Vec<DetectorReport>,
    pub session_id: Option<String>,
    pub processing_time_ms: f64,
}

impl DlpEngine {
    pub fn scan_protocol(&self, caller: &Caller, req: &ProtocolRequest) -> DlpResult<ProtocolResult> {
        let t0 = std::time::Instant::now();
        if req.body.to_string().len() > self.cfg.limits.max_text_bytes * 2 {
            return Err(DlpError::TooLarge("payload exceeds size limit".into()));
        }
        let proto = req.protocol.unwrap_or_else(|| detect_protocol(&req.body));
        let ex = extract(&req.body, proto, req.direction);
        let policy_id = req.policy_id.clone().unwrap_or_else(|| self.cfg.default_policy.clone());
        let policy = self.policy(&policy_id).ok_or_else(|| DlpError::NotFound(format!("policy '{policy_id}'")))?;

        // de-duplicate identical (direction, text) pairs: conversation history repeats a lot
        let mut uniq: Vec<(Direction, &str)> = Vec::new();
        let mut index: HashMap<(Direction, &str), usize> = HashMap::new();
        let mut slot_to_uniq: Vec<usize> = Vec::with_capacity(ex.slots.len());
        for s in &ex.slots {
            let k = (s.direction, s.text.as_str());
            let i = *index.entry(k).or_insert_with(|| {
                uniq.push(k);
                uniq.len() - 1
            });
            slot_to_uniq.push(i);
        }
        // anonymize mode must share one vault session across all slots
        let session = if req.mode == Mode::Anonymize {
            Some(req.session_id.clone().unwrap_or_else(|| {
                use rand::RngCore;
                let mut b = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut b);
                hex::encode(b)
            }))
        } else {
            req.session_id.clone()
        };
        let detect_reqs: Vec<DetectRequest> = uniq
            .iter()
            .map(|(d, t)| {
                let mut r = DetectRequest::new(t);
                r.direction = *d;
                r.policy_id = Some(policy_id.clone());
                r.session_id = session.clone();
                r.mode = Some(req.mode);
                r.nonce_placeholders = req.nonce_placeholders;
                r
            })
            .collect();
        let mut results: Vec<DetectResponse> = Vec::with_capacity(detect_reqs.len());
        for chunk in detect_reqs.chunks(self.cfg.limits.max_batch.max(1)) {
            // keep a single vault session consistent: process sequentially per chunk, parallel inside
            for r in self.process_many(caller, chunk) {
                results.push(r?);
            }
        }

        let mut decision = Verdict::Allow;
        let mut blocked_reason: Option<String> = None;
        let mut degraded = false;
        let mut warnings: Vec<String> = Vec::new();
        let mut findings = Vec::new();
        let mut unmod: Vec<String> = Vec::new();
        let mut edits: Vec<Edit> = Vec::new();
        let mut drops: Vec<String> = Vec::new();
        let mut detector_status: Vec<DetectorReport> = Vec::new();
        for r in &results {
            degraded |= r.degraded;
            for w in &r.warnings {
                if !warnings.contains(w) {
                    warnings.push(w.clone());
                }
            }
            if detector_status.is_empty() {
                detector_status = r.detector_status.clone();
            }
            if r.decision == Verdict::Blocked && blocked_reason.is_none() {
                blocked_reason = r.blocked_reason.clone();
                decision = Verdict::Blocked;
            }
        }
        for (si, slot) in ex.slots.iter().enumerate() {
            let r = &results[slot_to_uniq[si]];
            let acts = r.entities.iter().any(|e| e.action.modifies() || e.action == Action::Block);
            if r.decision == Verdict::Modified && decision == Verdict::Allow {
                decision = Verdict::Modified;
            }
            if !slot.modifiable && acts && r.decision != Verdict::Blocked {
                let msg = format!("sensitive data in integrity-protected field '{}' at {}", slot.kind, slot.pointer);
                match (policy.unmodifiable_action.as_str(), &slot.container) {
                    ("block", _) => {
                        decision = Verdict::Blocked;
                        blocked_reason.get_or_insert_with(|| format!("{msg}: policy requires block (cannot edit signed/integrity-protected content)"));
                    }
                    ("drop", Some(c)) => {
                        // desensitize by removing the whole signed block (text + signature): the content is
                        // not forwarded, the rest of the payload is sanitized and passed on
                        drops.push(c.clone());
                        warnings.push(format!("{msg}: block removed (policy unmodifiable_action=drop)"));
                        if decision == Verdict::Allow {
                            decision = Verdict::Modified;
                        }
                    }
                    _ => warnings.push(format!("{msg}: left unchanged (policy unmodifiable_action=audit or no removable container)")),
                }
                unmod.push(msg);
            }
            if slot.modifiable && r.decision != Verdict::Blocked {
                if let Some(new_text) = &r.sanitized_text {
                    if new_text != &slot.text {
                        edits.push(Edit { pointer: slot.pointer.clone(), sub: slot.sub.clone(), new_text: new_text.clone() });
                    }
                }
            }
            if !r.entities.is_empty() {
                findings.push(SlotFinding { pointer: format!("{}{}", slot.pointer, slot.sub.clone().unwrap_or_default()), kind: slot.kind, direction: slot.direction, modifiable: slot.modifiable, decision: r.decision, entities: r.entities.clone() });
            }
        }
        let mut body = None;
        if decision != Verdict::Blocked && req.mode != Mode::Detect {
            let mut b = req.body.clone();
            // edits first (pointers are still valid), then removals
            let edits: Vec<Edit> = edits.into_iter().filter(|e| !drops.iter().any(|d| e.pointer.starts_with(d.as_str()))).collect();
            apply_edits(&mut b, &edits).map_err(|e| DlpError::Internal(format!("could not apply edits safely: {e}")))?;
            remove_elements(&mut b, &drops).map_err(|e| DlpError::Internal(format!("could not remove block safely: {e}")))?;
            body = Some(b);
        }
        Ok(ProtocolResult {
            protocol: proto.name(),
            decision,
            blocked_reason,
            body,
            slots_scanned: ex.slots.len(),
            unique_texts_processed: uniq.len(),
            slots_skipped: ex.skipped,
            findings,
            unmodifiable_findings: unmod,
            degraded,
            warnings,
            detector_status,
            session_id: session,
            processing_time_ms: t0.elapsed().as_secs_f64() * 1000.0,
        })
    }
}
