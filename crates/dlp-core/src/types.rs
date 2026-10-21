use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(Self::Low),
            "medium" | "mid" => Some(Self::Medium),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Disposition applied to an entity. Ordered by severity so the strictest wins on ties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Action {
    Pass,
    Audit,
    Mask,
    Redact,
    Replace,
    Anonymize,
    Block,
}

impl Action {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "PASS" => Some(Self::Pass),
            "AUDIT" => Some(Self::Audit),
            "MASK" => Some(Self::Mask),
            "REDACT" => Some(Self::Redact),
            "REPLACE" => Some(Self::Replace),
            "ANONYMIZE" => Some(Self::Anonymize),
            "BLOCK" => Some(Self::Block),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Audit => "AUDIT",
            Self::Mask => "MASK",
            Self::Redact => "REDACT",
            Self::Replace => "REPLACE",
            Self::Anonymize => "ANONYMIZE",
            Self::Block => "BLOCK",
        }
    }
    /// Does this action modify the text?
    pub fn modifies(&self) -> bool {
        matches!(self, Self::Mask | Self::Redact | Self::Replace | Self::Anonymize)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Request,
    Response,
    ToolInput,
    ToolOutput,
}

impl Direction {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "request" | "prompt" => Some(Self::Request),
            "response" => Some(Self::Response),
            "tool_input" => Some(Self::ToolInput),
            "tool_output" => Some(Self::ToolOutput),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
            Self::ToolInput => "tool_input",
            Self::ToolOutput => "tool_output",
        }
    }
}

/// How much evidence backs an entity. Used by the merger: deterministic evidence beats
/// statistical evidence regardless of the raw confidence number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// Statistical model output (NER). Needs corroboration for high-risk decisions.
    Model,
    /// Dictionary / loose pattern without a checksum or strong format.
    Pattern,
    /// Strong format + validator (checksum, entropy, fixed vendor prefix, ...).
    Validated,
}

/// A candidate entity as emitted by one detector (before merging / policy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entity {
    pub entity_type: String,
    /// UTF-8 byte offsets, `[start, end)`.
    pub start: usize,
    pub end: usize,
    pub confidence: f32,
    pub risk_level: RiskLevel,
    pub detector: String,
    pub rule_id: String,
    pub action: Action,
    /// Masked context snippet (never contains the matched value itself).
    #[serde(default)]
    pub context: String,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    pub evidence: Evidence,
    /// Rule category (pii, credential, financial, internal, business...). Not serialized to
    /// clients but needed by the policy layer.
    #[serde(default)]
    pub category: String,
    /// Rule priority (higher wins on ties).
    #[serde(default)]
    pub priority: i32,
    /// Entity values of this kind can never be restored from the vault.
    #[serde(default)]
    pub irreversible: bool,
}

impl Entity {
    pub fn new(entity_type: &str, start: usize, end: usize, detector: &str, rule_id: &str) -> Self {
        Entity {
            entity_type: entity_type.to_string(),
            start,
            end,
            confidence: 0.5,
            risk_level: RiskLevel::Medium,
            detector: detector.to_string(),
            rule_id: rule_id.to_string(),
            action: Action::Audit,
            context: String::new(),
            metadata: BTreeMap::new(),
            evidence: Evidence::Pattern,
            category: String::new(),
            priority: 0,
            irreversible: false,
        }
    }
    pub fn len(&self) -> usize {
        self.end - self.start
    }
    pub fn is_empty(&self) -> bool {
        self.end <= self.start
    }
    pub fn overlaps(&self, other: &Entity) -> bool {
        self.start < other.end && other.start < self.end
    }
    pub fn contains(&self, other: &Entity) -> bool {
        self.start <= other.start && other.end <= self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorState {
    Ready,
    /// Works but with reduced capability (e.g. Hyperscan missing, regex fallback in use).
    Degraded,
    Unavailable,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorStatus {
    pub name: String,
    pub state: DetectorState,
    pub message: String,
    pub version: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectorMetrics {
    pub calls: u64,
    pub errors: u64,
    pub total_us: u64,
    pub max_us: u64,
    pub entities: u64,
}

#[derive(Debug, thiserror::Error, Clone)]
pub enum DlpError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("input exceeds limit: {0}")]
    TooLarge(String),
    #[error("detector unavailable: {0}")]
    DetectorUnavailable(String),
    #[error("detector timeout: {0}")]
    Timeout(String),
    #[error("rules error: {0}")]
    Rules(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("policy error: {0}")]
    Policy(String),
    #[error("vault error: {0}")]
    Vault(String),
    #[error("permission denied: {0}")]
    Forbidden(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl DlpError {
    /// Stable numeric code shared with the C ABI.
    pub fn code(&self) -> i32 {
        match self {
            DlpError::InvalidInput(_) => 2,
            DlpError::TooLarge(_) => 3,
            DlpError::DetectorUnavailable(_) => 4,
            DlpError::Timeout(_) => 5,
            DlpError::Rules(_) => 6,
            DlpError::Storage(_) => 7,
            DlpError::Policy(_) => 8,
            DlpError::Vault(_) => 9,
            DlpError::Forbidden(_) => 10,
            DlpError::NotFound(_) => 11,
            DlpError::Internal(_) => 99,
        }
    }
}

pub type DlpResult<T> = Result<T, DlpError>;

/// Normalised entity type vocabulary used by built-in rules. Custom types are allowed.
pub mod entity {
    pub const PERSON: &str = "PERSON";
    pub const PHONE: &str = "PHONE_NUMBER";
    pub const EMAIL: &str = "EMAIL_ADDRESS";
    pub const CN_ID_CARD: &str = "CN_ID_CARD";
    pub const BANK_CARD: &str = "BANK_CARD";
    pub const CREDIT_CARD: &str = "CREDIT_CARD";
    pub const API_KEY: &str = "API_KEY";
    pub const PRIVATE_KEY: &str = "PRIVATE_KEY";
    pub const PASSWORD: &str = "PASSWORD";
    pub const ADDRESS: &str = "ADDRESS";
    pub const LOCATION: &str = "LOCATION";
    pub const ORGANIZATION: &str = "ORGANIZATION";
    pub const IP_INTERNAL: &str = "IP_INTERNAL";
    pub const DB_CONNECTION: &str = "DB_CONNECTION_STRING";
}

/// Verified identity of the party calling the engine. In the HTTP server this is built from the
/// authentication layer (API key -> tenant + scopes) and **never** from request bodies; for the
/// in-process C ABI / CLI the host application is trusted to supply it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub tenant_id: String,
    pub subject: String,
    pub scopes: Vec<String>,
}

impl Caller {
    pub fn new(tenant: &str, subject: &str, scopes: &[&str]) -> Self {
        Caller { tenant_id: tenant.into(), subject: subject.into(), scopes: scopes.iter().map(|s| s.to_string()).collect() }
    }
    /// Trusted in-process caller (CLI, tests, embedded library use).
    pub fn local_admin() -> Self {
        Caller::new("local", "local-admin", &["*"])
    }
    pub fn has_scope(&self, s: &str) -> bool {
        self.scopes.iter().any(|x| x == "*" || x == s)
    }
}
