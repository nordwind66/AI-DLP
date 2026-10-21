//! Policy model and evaluation: maps a detected [`Entity`] (+ direction) to an [`Action`].
//!
//! Resolution order (most specific wins): `rule_id` > `entity_type` > `category` > `risk_level` >
//! policy default. Within the same specificity a direction-specific rule beats an `any` rule, then
//! the higher `priority` wins, then the stricter action. Entities under the effective confidence
//! threshold are suppressed (and counted), never silently upgraded.
use dlp_core::{Action, Direction, Entity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    /// A mandatory detector failing => the request is blocked.
    FailClosed,
    /// Continue with what is available, but flag the degradation in the response and audit log.
    FailOpenWithAudit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchKind {
    RuleId,
    EntityType,
    Category,
    RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub match_kind: MatchKind,
    pub match_value: String,
    /// `None` = any direction.
    #[serde(default)]
    pub direction: Option<Direction>,
    pub action: Action,
    #[serde(default)]
    pub min_confidence: Option<f32>,
    /// Text for `REPLACE` (or a custom redaction label for `REDACT`).
    #[serde(default)]
    pub replacement: Option<String>,
    #[serde(default)]
    pub priority: i32,
}

fn d_detectors() -> Vec<String> {
    vec!["regex".into(), "secret".into(), "dictionary".into()]
}
fn d_stream() -> String {
    "strict".into()
}
fn d_trigger() -> String {
    "always".into()
}
fn d_unmod() -> String {
    "block".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDef {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub fail_mode: FailMode,
    #[serde(default = "d_detectors")]
    pub enabled_detectors: Vec<String>,
    /// Detectors whose failure is governed by `fail_mode`. Others degrade with a warning.
    #[serde(default)]
    pub mandatory_detectors: Vec<String>,
    #[serde(default = "d_default_action")]
    pub default_action: Action,
    #[serde(default)]
    pub min_confidence: f32,
    /// "strict" (buffer the full response) | "window" (bounded hold-back, rule detectors only)
    #[serde(default = "d_stream")]
    pub stream_mode: String,
    /// "always" | "auto" (skip NLP for text with no letters/CJK and for very short text)
    #[serde(default = "d_trigger")]
    pub nlp_trigger: String,
    /// What to do when a sensitive value sits in a field we must not modify (signed thinking...).
    #[serde(default = "d_unmod")]
    pub unmodifiable_action: String,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
}
fn d_default_action() -> Action {
    Action::Audit
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub action: Action,
    pub replacement: Option<String>,
    /// Entity is below the threshold of the matching rule / policy: drop it.
    pub suppressed: bool,
}

impl PolicyDef {
    pub fn decide(&self, e: &Entity, dir: Direction) -> Decision {
        let mut best: Option<(&PolicyRule, (u8, u8, i32, Action))> = None;
        for r in &self.rules {
            if let Some(d) = r.direction {
                if d != dir {
                    continue;
                }
            }
            let spec = match r.match_kind {
                MatchKind::RuleId if r.match_value == e.rule_id => 4,
                MatchKind::EntityType if r.match_value == e.entity_type => 3,
                MatchKind::Category if r.match_value == e.category => 2,
                MatchKind::RiskLevel if r.match_value == e.risk_level.as_str() => 1,
                _ => continue,
            };
            let key = (spec, r.direction.is_some() as u8, r.priority, r.action);
            if best.as_ref().map(|(_, k)| key > *k).unwrap_or(true) {
                best = Some((r, key));
            }
        }
        let (action, replacement, thr) = match best {
            Some((r, _)) => (r.action, r.replacement.clone(), r.min_confidence.unwrap_or(self.min_confidence)),
            None => (self.default_action, None, self.min_confidence),
        };
        Decision { action, replacement, suppressed: e.confidence < thr }
    }

    pub fn detector_enabled(&self, name: &str) -> bool {
        self.enabled_detectors.iter().any(|d| d == name)
    }
    pub fn is_mandatory(&self, name: &str) -> bool {
        self.mandatory_detectors.iter().any(|d| d == name)
    }
}

/// Parse a policy file (`rules/policies.toml`-style JSON value list) — kept tiny on purpose.
pub fn policies_from_json(v: &serde_json::Value) -> Result<Vec<PolicyDef>, String> {
    serde_json::from_value(v.clone()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dlp_core::RiskLevel;

    fn pol() -> PolicyDef {
        PolicyDef {
            id: "t".into(),
            name: "t".into(),
            description: String::new(),
            fail_mode: FailMode::FailClosed,
            enabled_detectors: d_detectors(),
            mandatory_detectors: vec![],
            default_action: Action::Audit,
            min_confidence: 0.3,
            stream_mode: "strict".into(),
            nlp_trigger: "always".into(),
            unmodifiable_action: "block".into(),
            rules: vec![
                PolicyRule { match_kind: MatchKind::EntityType, match_value: "PHONE_NUMBER".into(), direction: None, action: Action::Mask, min_confidence: None, replacement: None, priority: 0 },
                PolicyRule { match_kind: MatchKind::Category, match_value: "credential".into(), direction: None, action: Action::Redact, min_confidence: None, replacement: None, priority: 0 },
                PolicyRule { match_kind: MatchKind::EntityType, match_value: "PRIVATE_KEY".into(), direction: None, action: Action::Block, min_confidence: None, replacement: None, priority: 0 },
                PolicyRule { match_kind: MatchKind::EntityType, match_value: "PHONE_NUMBER".into(), direction: Some(Direction::Response), action: Action::Redact, min_confidence: None, replacement: None, priority: 0 },
            ],
        }
    }
    fn ent(t: &str, cat: &str) -> Entity {
        let mut e = Entity::new(t, 0, 5, "regex", "r1");
        e.category = cat.into();
        e.confidence = 0.9;
        e.risk_level = RiskLevel::High;
        e
    }
    #[test]
    fn specificity_and_direction() {
        let p = pol();
        assert_eq!(p.decide(&ent("PHONE_NUMBER", "pii"), Direction::Request).action, Action::Mask);
        assert_eq!(p.decide(&ent("PHONE_NUMBER", "pii"), Direction::Response).action, Action::Redact);
        // entity_type PRIVATE_KEY (3) beats category credential (2)
        assert_eq!(p.decide(&ent("PRIVATE_KEY", "credential"), Direction::Request).action, Action::Block);
        assert_eq!(p.decide(&ent("API_KEY", "credential"), Direction::Request).action, Action::Redact);
        assert_eq!(p.decide(&ent("PERSON", "pii"), Direction::Request).action, Action::Audit);
    }
    #[test]
    fn threshold_suppresses() {
        let p = pol();
        let mut e = ent("PERSON", "pii");
        e.confidence = 0.1;
        assert!(p.decide(&e, Direction::Request).suppressed);
    }
}
