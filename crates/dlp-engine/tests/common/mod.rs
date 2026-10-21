#![allow(dead_code)]
use dlp_core::*;
use dlp_engine::*;
use std::sync::Arc;

pub fn rules_dir() -> String {
    format!("{}/../../rules", env!("CARGO_MANIFEST_DIR"))
}

/// Engine over an in-memory DB bootstrapped from the shipped rules (gitleaks + builtin), rules only.
pub fn engine() -> Arc<DlpEngine> {
    engine_with(|_| {})
}

pub fn engine_with(f: impl FnOnce(&mut EngineConfig)) -> Arc<DlpEngine> {
    let mut cfg = EngineConfig::default();
    cfg.db_path = ":memory:".into();
    cfg.rules_dir = Some(rules_dir());
    f(&mut cfg);
    DlpEngine::open(cfg).expect("engine")
}

pub fn admin() -> Caller {
    Caller::local_admin()
}

pub fn user(tenant: &str, subject: &str) -> Caller {
    Caller::new(tenant, subject, &["detect", "sanitize", "anonymize", "deanonymize"])
}

pub fn req(text: &str, policy: &str, mode: Mode) -> DetectRequest {
    let mut r = DetectRequest::new(text);
    r.policy_id = Some(policy.into());
    r.mode = Some(mode);
    r.detectors = Some(vec!["regex".into(), "secret".into(), "dictionary".into()]);
    r
}

/// Valid synthetic China ID: region 110101, born 1990-03-07, seq 002, correct check digit.
pub const VALID_ID: &str = "11010119900307002X";
/// Synthetic AWS-style access key id (random characters, not a real credential).
pub const FAKE_AWS: &str = "AKIAZ3XQKVN5TLWM7EPD";
pub const FAKE_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\nVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u+qKhbwKfBstIs+bMY2Zkp18gnTxK\nLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW/VDL5AaWTg0nLVkjRo\n-----END RSA PRIVATE KEY-----";
