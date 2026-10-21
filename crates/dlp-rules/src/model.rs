//! Plain-data rule model. This is what lives in SQLite and in version snapshots; it is compiled
//! into an executable [`crate::RuleSet`] by `RuleSet::compile`.
use serde::{Deserialize, Serialize};

fn d_true() -> bool {
    true
}
fn d_conf() -> f32 {
    0.85
}
fn d_window() -> usize {
    40
}
fn d_or() -> String {
    "OR".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PatternDef {
    pub pattern: String,
    /// "regex" (matched against text) or "path" (gitleaks file-path regex; not applicable to prompt text).
    #[serde(default = "d_regex")]
    pub kind: String,
}
fn d_regex() -> String {
    "regex".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidatorDef {
    pub name: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AllowlistDef {
    #[serde(default)]
    pub description: String,
    /// "OR" | "AND" (gitleaks `condition`)
    #[serde(default = "d_or")]
    pub condition: String,
    /// "" (secret) | "match" | "line"
    #[serde(default)]
    pub regex_target: String,
    #[serde(default)]
    pub regexes: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub stopwords: Vec<String>,
    #[serde(default)]
    pub commits: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequiredDef {
    pub rule_id: String,
    pub within_lines: Option<i64>,
    pub within_columns: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleDef {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// pii | contact | financial | credential | internal | business | custom
    pub category: String,
    pub entity_type: String,
    /// low | medium | high | critical
    pub risk_level: String,
    /// regex | secret | dictionary
    pub engine: String,
    #[serde(default)]
    pub patterns: Vec<PatternDef>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub entropy: f64,
    #[serde(default)]
    pub secret_group: i64,
    #[serde(default)]
    pub validators: Vec<ValidatorDef>,
    #[serde(default)]
    pub context_keywords: Vec<String>,
    /// "boost" (raise confidence when found) | "require" (drop unless found)
    #[serde(default)]
    pub context_mode: String,
    #[serde(default = "d_window")]
    pub context_window: usize,
    #[serde(default = "d_conf")]
    pub confidence: f32,
    /// "validated" | "pattern"
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default = "d_true")]
    pub enabled: bool,
    #[serde(default)]
    pub irreversible: bool,
    /// gitleaks `skipReport`: helper rule only reported when it satisfies another rule's `required`.
    #[serde(default)]
    pub skip_report: bool,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub source_version: String,
    #[serde(default)]
    pub allowlists: Vec<AllowlistDef>,
    #[serde(default)]
    pub required: Vec<RequiredDef>,
    /// native | translated | unsupported
    #[serde(default)]
    pub compat: String,
    #[serde(default)]
    pub compat_note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DictEntry {
    pub rule_id: String,
    pub term: String,
    #[serde(default)]
    pub case_sensitive: bool,
    #[serde(default = "d_true")]
    pub whole_word: bool,
}

/// A complete, self-consistent rule set (what a reload reads in one transaction).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct RuleSetDef {
    pub version: i64,
    pub rules: Vec<RuleDef>,
    #[serde(default)]
    pub global_allowlists: Vec<AllowlistDef>,
    #[serde(default)]
    pub dictionaries: Vec<DictEntry>,
}

impl RuleDef {
    /// Minimal constructor used by tests and the built-in importer.
    pub fn simple(id: &str, entity_type: &str, category: &str, risk: &str, regex: &str) -> Self {
        RuleDef {
            id: id.into(),
            name: id.into(),
            description: String::new(),
            category: category.into(),
            entity_type: entity_type.into(),
            risk_level: risk.into(),
            engine: "regex".into(),
            patterns: vec![PatternDef { pattern: regex.into(), kind: "regex".into() }],
            keywords: vec![],
            entropy: 0.0,
            secret_group: 0,
            validators: vec![],
            context_keywords: vec![],
            context_mode: String::new(),
            context_window: 40,
            confidence: 0.85,
            evidence: "pattern".into(),
            priority: 0,
            enabled: true,
            irreversible: false,
            skip_report: false,
            source: "builtin".into(),
            source_version: String::new(),
            allowlists: vec![],
            required: vec![],
            compat: "native".into(),
            compat_note: String::new(),
        }
    }
}
