//! Wire-level request/response types shared by the HTTP server, C ABI and CLI.
//! Offsets in responses are Unicode code points (`start`/`end`) plus raw UTF-8 byte offsets.
use dlp_core::{Action, DetectorState, Direction, RiskLevel};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Report only; text is never modified.
    Detect,
    /// Irreversible modification (MASK / REDACT / REPLACE; ANONYMIZE degrades to REDACT).
    Sanitize,
    /// Reversible anonymization through the session vault.
    Anonymize,
}

fn d_dir() -> Direction {
    Direction::Request
}
fn d_lang() -> String {
    "auto".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectRequest {
    pub text: String,
    #[serde(default = "d_dir")]
    pub direction: Direction,
    #[serde(default = "d_lang")]
    pub language: String,
    #[serde(default)]
    pub policy_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub mode: Option<Mode>,
    /// Restrict the result to these entity types (empty = all the policy cares about).
    #[serde(default)]
    pub entities: Vec<String>,
    /// Override the policy's detector list (cannot enable detectors the policy forbids for mandatory use).
    #[serde(default)]
    pub detectors: Option<Vec<String>>,
    /// Use `[TYPE_N#nonce]` placeholders (anonymize mode).
    #[serde(default)]
    pub nonce_placeholders: Option<bool>,
    /// Debug only: echo the matched value in each entity. Requires the `debug:reveal` scope.
    #[serde(default)]
    pub reveal_values: bool,
    /// Per-request action overrides by entity type. Only *stricter* actions than the policy's are honoured
    /// (a caller can add BLOCK/REDACT but can never downgrade what the policy demands).
    #[serde(default)]
    pub action_overrides: std::collections::HashMap<String, Action>,
    /// Internal: exhaustive rule evaluation (no keyword gating) for window-mode stream scanning.
    #[serde(default)]
    pub exhaustive: bool,
}

impl DetectRequest {
    pub fn new(text: &str) -> Self {
        DetectRequest { text: text.to_string(), direction: Direction::Request, language: "auto".into(), policy_id: None, session_id: None, mode: None, entities: vec![], detectors: None, nonce_placeholders: None, reveal_values: false, action_overrides: Default::default(), exhaustive: false }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EntityOut {
    pub entity_type: String,
    /// Unicode code point offsets
    pub start: usize,
    pub end: usize,
    pub byte_start: usize,
    pub byte_end: usize,
    pub confidence: f32,
    pub risk_level: RiskLevel,
    pub detector: String,
    pub rule_id: String,
    /// policy action for this entity
    pub action: Action,
    /// action that was actually applied (differs e.g. when ANONYMIZE degraded to REDACT)
    pub applied_action: Action,
    pub context: String,
    pub metadata: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// text that replaced this entity in `sanitized_text` (placeholder / masked value; never the original)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replacement: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectorReport {
    pub name: String,
    pub state: DetectorState,
    pub message: String,
    /// enabled by the effective policy for this request
    pub enabled: bool,
    /// actually executed for this request
    pub ran: bool,
    /// failure during this request (the detector was needed but did not deliver)
    pub error: Option<String>,
    pub mandatory: bool,
    pub ms: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// nothing to act on
    Allow,
    /// text was (or would be, in detect mode) modified / flagged
    Modified,
    Blocked,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectResponse {
    pub decision: Verdict,
    pub blocked_reason: Option<String>,
    pub entities: Vec<EntityOut>,
    /// `None` in detect mode and when blocked
    pub sanitized_text: Option<String>,
    pub detector_status: Vec<DetectorReport>,
    /// some enabled detector could not run: results may be incomplete
    pub degraded: bool,
    pub warnings: Vec<String>,
    pub policy_id: String,
    pub ruleset_version: i64,
    pub direction: Direction,
    pub mode: Mode,
    pub session_id: Option<String>,
    /// distinct actions present in `entities` (summary)
    pub actions: Vec<Action>,
    pub suppressed_low_confidence: usize,
    pub processing_time_ms: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReloadReport {
    pub changed: bool,
    pub ruleset_version: i64,
    pub rules_enabled: usize,
    pub fingerprint: String,
    pub hyperscan_active: bool,
    pub hyperscan_rejected_rules: usize,
    pub path_only_skipped: Vec<String>,
    pub policies: usize,
    pub compile_ms: u128,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeanonymizeOut {
    pub text: String,
    pub restored: usize,
    pub unknown_placeholders: usize,
    /// response-side detection that gated the restore (when requested)
    pub response_check: Option<DetectResponse>,
}
