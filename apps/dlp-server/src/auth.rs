//! API-key authentication. Identity (tenant, subject, scopes) comes ONLY from the server-side key
//! table; a `tenant_id` in a request body is never trusted (it must match or the call is refused).
use dlp_core::Caller;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Deserialize)]
pub struct KeyEntry {
    pub id: String,
    /// lowercase hex SHA-256 of the API key (keys themselves are never stored)
    pub key_sha256: String,
    pub tenant: String,
    pub subject: String,
    pub scopes: Vec<String>,
}

pub struct Auth {
    keys: Vec<(Vec<u8>, KeyEntry)>,
    pub insecure: bool,
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Auth {
    pub fn from_file(path: &str) -> Result<Auth, String> {
        let t = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        let entries: Vec<KeyEntry> = serde_json::from_str(&t).map_err(|e| format!("{path}: {e}"))?;
        let mut keys = vec![];
        for e in entries {
            let h = hex::decode(&e.key_sha256).map_err(|_| format!("key '{}': key_sha256 is not hex", e.id))?;
            if h.len() != 32 {
                return Err(format!("key '{}': key_sha256 must be 32 bytes", e.id));
            }
            keys.push((h, e));
        }
        if keys.is_empty() {
            return Err("api key file is empty".into());
        }
        Ok(Auth { keys, insecure: false })
    }
    pub fn insecure() -> Auth {
        Auth { keys: vec![], insecure: true }
    }
    pub fn authenticate(&self, presented: Option<&str>) -> Option<Caller> {
        if self.insecure {
            return Some(Caller::new("dev", "dev", &["*"]));
        }
        let key = presented?;
        let digest = Sha256::digest(key.as_bytes());
        let mut found = None;
        for (h, e) in &self.keys {
            // no early exit: constant work per attempt
            if ct_eq(h, &digest) {
                found = Some(e);
            }
        }
        found.map(|e| Caller { tenant_id: e.tenant.clone(), subject: e.subject.clone(), scopes: e.scopes.clone() })
    }
}
