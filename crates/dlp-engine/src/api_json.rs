//! JSON request schema shared by the HTTP API and the C ABI (single source of truth).
use crate::api::*;
use dlp_core::*;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Body {
    pub text: Option<String>,
    /// structured LLM payload (OpenAI / Anthropic / generic JSON) instead of `text`
    pub payload: Option<Value>,
    pub protocol: Option<String>,
    pub direction: Option<String>,
    pub language: Option<String>,
    pub policy_id: Option<String>,
    pub session_id: Option<String>,
    /// never trusted by the HTTP server (must equal the authenticated tenant); used by the in-process C ABI
    pub tenant_id: Option<String>,
    pub mode: Option<String>,
    pub entities: Option<Vec<String>>,
    pub detectors: Option<Vec<String>>,
    pub actions: Option<HashMap<String, String>>,
    pub nonce_placeholders: Option<bool>,
    pub reveal_values: Option<bool>,
}

pub fn mode_of(s: Option<&str>, forced: Option<Mode>) -> DlpResult<Mode> {
    if let Some(m) = forced {
        return Ok(m);
    }
    match s.unwrap_or("detect") {
        "detect" => Ok(Mode::Detect),
        "sanitize" => Ok(Mode::Sanitize),
        "anonymize" => Ok(Mode::Anonymize),
        _ => Err(DlpError::InvalidInput("mode must be detect|sanitize|anonymize".into())),
    }
}

pub fn to_request(b: &Body, forced: Option<Mode>) -> DlpResult<DetectRequest> {
    let text = b.text.clone().ok_or_else(|| DlpError::InvalidInput("field 'text' is required".into()))?;
    let mut r = DetectRequest::new(&text);
    if let Some(d) = &b.direction {
        r.direction = Direction::parse(d).ok_or_else(|| DlpError::InvalidInput("direction must be request|response|tool_input|tool_output".into()))?;
    }
    if let Some(l) = &b.language {
        r.language = l.clone();
    }
    r.policy_id = b.policy_id.clone();
    r.session_id = b.session_id.clone();
    r.mode = Some(mode_of(b.mode.as_deref(), forced)?);
    r.entities = b.entities.clone().unwrap_or_default();
    r.detectors = b.detectors.clone();
    r.nonce_placeholders = b.nonce_placeholders;
    r.reveal_values = b.reveal_values.unwrap_or(false);
    if let Some(a) = &b.actions {
        for (k, v) in a {
            r.action_overrides.insert(k.clone(), Action::parse(v).ok_or_else(|| DlpError::InvalidInput("unknown action in 'actions'".into()))?);
        }
    }
    Ok(r)
}

/// Run a text or structured request end to end and return the JSON response value.
pub fn run_body(engine: &crate::DlpEngine, caller: &Caller, b: &Body, forced: Option<Mode>) -> DlpResult<Value> {
    if let Some(payload) = b.payload.clone() {
        let mode = mode_of(b.mode.as_deref(), forced)?;
        let protocol = match &b.protocol {
            Some(p) => Some(dlp_protocol::Protocol::parse(p).ok_or_else(|| DlpError::InvalidInput("unknown protocol".into()))?),
            None => None,
        };
        let req = crate::protocol_scan::ProtocolRequest {
            body: payload,
            protocol,
            direction: b.direction.as_deref().and_then(Direction::parse).unwrap_or(Direction::Request),
            policy_id: b.policy_id.clone(),
            session_id: b.session_id.clone(),
            mode,
            nonce_placeholders: b.nonce_placeholders,
        };
        let r = engine.scan_protocol(caller, &req)?;
        return serde_json::to_value(r).map_err(|e| DlpError::Internal(e.to_string()));
    }
    let req = to_request(b, forced)?;
    let r = engine.process(caller, &req)?;
    serde_json::to_value(r).map_err(|e| DlpError::Internal(e.to_string()))
}
