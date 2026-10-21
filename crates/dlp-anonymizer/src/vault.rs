//! Session-scoped Token Vault for reversible anonymization.
//!
//! What we took from LLM Guard (`llm_guard/vault.py`, `input_scanners/anonymize.py::_anonymize`,
//! `output_scanners/deanonymize.py`) and what we changed:
//!
//! | LLM Guard                                        | here                                                     |
//! |--------------------------------------------------|----------------------------------------------------------|
//! | `[REDACTED_PERSON_1]` placeholders, per-type idx  | same scheme `[PERSON_1]`; same value -> same placeholder  |
//! | Vault = flat list of tuples (global)             | (tenant, session) keyed, owner-bound, TTL, size limits    |
//! | no auth on restore                               | scope check + owner check + tenant isolation              |
//! | fuzzy / case-insensitive / chained `str.replace` | single-pass exact match of *issued* placeholders only     |
//! | values kept as plain strings                     | `Zeroizing` storage, never logged, dropped on expiry      |
//!
//! Default storage is in-memory only. Nothing sensitive is ever written to disk.
use dlp_core::{Caller, DlpError, DlpResult};
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use rand::RngCore;
use regex::Regex;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;
const SHARDS: usize = 16;

#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub ttl: Duration,
    pub max_sessions: usize,
    pub max_entries_per_session: usize,
    pub max_value_bytes: usize,
    /// `[PERSON_1#a1b2c3]` instead of `[PERSON_1]`: placeholders from another session or invented
    /// by a model/attacker can never collide with ours.
    pub nonce_placeholders: bool,
}
impl Default for VaultConfig {
    fn default() -> Self {
        VaultConfig { ttl: Duration::from_secs(3600), max_sessions: 100_000, max_entries_per_session: 5_000, max_value_bytes: 4096, nonce_placeholders: false }
    }
}

struct Entry {
    entity_type: String,
    value: Zeroizing<String>,
}

struct Session {
    owner: String,
    created: Instant,
    expires: Instant,
    nonce: String,
    nonce_mode: bool,
    entries: HashMap<String, Entry>,
    by_value: HashMap<(String, [u8; 32]), String>,
    counters: HashMap<String, u32>,
}

type Key = (String, String); // (tenant, session_id)

pub struct Vault {
    shards: Vec<Mutex<HashMap<Key, Session>>>,
    cfg: VaultConfig,
    hmac_key: [u8; 32],
    sessions: AtomicU64,
    pub stat_restored: AtomicU64,
    pub stat_denied: AtomicU64,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DeanonymizeResult {
    pub text: String,
    pub restored: usize,
    /// placeholder-shaped tokens that are not issued by this session (forged / foreign): left untouched
    pub unknown_placeholders: usize,
}

pub fn placeholder_regex() -> &'static Regex {
    placeholder_re()
}

fn placeholder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\[[A-Z][A-Z0-9_]{0,40}_[0-9]{1,6}(?:#[0-9a-f]{6})?\]").unwrap())
}

impl Vault {
    pub fn new(cfg: VaultConfig) -> Vault {
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        Vault { shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(), cfg, hmac_key: k, sessions: AtomicU64::new(0), stat_restored: AtomicU64::new(0), stat_denied: AtomicU64::new(0) }
    }

    fn shard(&self, key: &Key) -> &Mutex<HashMap<Key, Session>> {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        key.hash(&mut h);
        &self.shards[(h.finish() as usize) % SHARDS]
    }

    fn value_tag(&self, value: &str) -> [u8; 32] {
        let mut m = HmacSha256::new_from_slice(&self.hmac_key).unwrap();
        m.update(value.as_bytes());
        m.finalize().into_bytes().into()
    }

    pub fn config(&self) -> &VaultConfig {
        &self.cfg
    }

    fn check_session_id(id: &str) -> DlpResult<()> {
        if id.is_empty() || id.len() > 128 || !id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':')) {
            return Err(DlpError::InvalidInput("session_id must be 1-128 chars of [A-Za-z0-9-_.:]".into()));
        }
        Ok(())
    }

    /// Obtain (or create) a session for `caller` and run `f` under the shard lock.
    /// Another subject of the same tenant gets the same opaque error as for a missing session.
    pub fn with_session<T>(&self, caller: &Caller, session_id: &str, create: bool, nonce_mode: Option<bool>, f: impl FnOnce(&mut SessionHandle) -> DlpResult<T>) -> DlpResult<T> {
        Self::check_session_id(session_id)?;
        let key: Key = (caller.tenant_id.clone(), session_id.to_string());
        let mut map = self.shard(&key).lock();
        let now = Instant::now();
        if let Some(s) = map.get(&key) {
            if s.expires <= now {
                map.remove(&key);
                self.sessions.fetch_sub(1, Ordering::Relaxed);
            }
        }
        if !map.contains_key(&key) {
            if !create {
                self.stat_denied.fetch_add(1, Ordering::Relaxed);
                return Err(DlpError::NotFound("vault session not found or expired".into()));
            }
            if self.sessions.load(Ordering::Relaxed) as usize >= self.cfg.max_sessions {
                return Err(DlpError::TooLarge("vault session limit reached".into()));
            }
            let mut nonce = [0u8; 3];
            rand::thread_rng().fill_bytes(&mut nonce);
            map.insert(
                key.clone(),
                Session {
                    owner: caller.subject.clone(),
                    created: now,
                    expires: now + self.cfg.ttl,
                    nonce: hex::encode(nonce),
                    nonce_mode: nonce_mode.unwrap_or(self.cfg.nonce_placeholders),
                    entries: HashMap::new(),
                    by_value: HashMap::new(),
                    counters: HashMap::new(),
                },
            );
            self.sessions.fetch_add(1, Ordering::Relaxed);
        }
        let s = map.get_mut(&key).unwrap();
        if s.owner != caller.subject && !caller.has_scope("vault:admin") {
            self.stat_denied.fetch_add(1, Ordering::Relaxed);
            return Err(DlpError::NotFound("vault session not found or expired".into()));
        }
        let mut h = SessionHandle { s, vault: self };
        f(&mut h)
    }

    /// Restore placeholders issued by this session. Requires the `deanonymize` scope.
    /// Single pass, exact match only, restored values are never re-scanned for placeholders.
    pub fn deanonymize(&self, caller: &Caller, session_id: &str, text: &str) -> DlpResult<DeanonymizeResult> {
        if !caller.has_scope("deanonymize") {
            self.stat_denied.fetch_add(1, Ordering::Relaxed);
            return Err(DlpError::Forbidden("missing scope 'deanonymize'".into()));
        }
        self.with_session(caller, session_id, false, None, |h| {
            let mut out = String::with_capacity(text.len());
            let (mut last, mut restored, mut unknown) = (0usize, 0usize, 0usize);
            for m in placeholder_re().find_iter(text) {
                out.push_str(&text[last..m.start()]);
                match h.s.entries.get(m.as_str()) {
                    Some(e) if h.s.nonce_mode == m.as_str().contains('#') => {
                        out.push_str(&e.value);
                        restored += 1;
                    }
                    _ => {
                        out.push_str(m.as_str());
                        unknown += 1;
                    }
                }
                last = m.end();
            }
            out.push_str(&text[last..]);
            h.vault.stat_restored.fetch_add(restored as u64, Ordering::Relaxed);
            Ok(DeanonymizeResult { text: out, restored, unknown_placeholders: unknown })
        })
    }

    /// Placeholders issued by this caller's session (read-only: never creates a session, no stats).
    /// Used to shield them from detection so that a model reply or a later turn that merely repeats
    /// `[PERSON_1]` is not re-detected, masked or re-anonymized.
    pub fn issued(&self, caller: &Caller, session_id: &str) -> Option<std::collections::HashSet<String>> {
        if Self::check_session_id(session_id).is_err() {
            return None;
        }
        let key: Key = (caller.tenant_id.clone(), session_id.to_string());
        let map = self.shard(&key).lock();
        let s = map.get(&key)?;
        if s.expires <= Instant::now() || (s.owner != caller.subject && !caller.has_scope("vault:admin")) {
            return None;
        }
        Some(s.entries.keys().cloned().collect())
    }

    pub fn purge(&self, caller: &Caller, session_id: &str) -> DlpResult<bool> {
        Self::check_session_id(session_id)?;
        let key: Key = (caller.tenant_id.clone(), session_id.to_string());
        let mut map = self.shard(&key).lock();
        match map.get(&key) {
            Some(s) if s.owner == caller.subject || caller.has_scope("vault:admin") => {
                map.remove(&key);
                self.sessions.fetch_sub(1, Ordering::Relaxed);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Drop expired sessions (call periodically). Values are zeroized on drop.
    pub fn sweep(&self) -> usize {
        let now = Instant::now();
        let mut n = 0;
        for sh in &self.shards {
            let mut m = sh.lock();
            let before = m.len();
            m.retain(|_, s| s.expires > now);
            n += before - m.len();
        }
        self.sessions.fetch_sub(n as u64, Ordering::Relaxed);
        n
    }

    pub fn session_count(&self) -> u64 {
        self.sessions.load(Ordering::Relaxed)
    }

    /// Test helper: shorten a session's lifetime.
    pub fn expire_now(&self, caller: &Caller, session_id: &str) {
        let key: Key = (caller.tenant_id.clone(), session_id.to_string());
        if let Some(s) = self.shard(&key).lock().get_mut(&key) {
            s.expires = Instant::now();
        }
    }
}

pub struct SessionHandle<'a> {
    s: &'a mut Session,
    vault: &'a Vault,
}

impl SessionHandle<'_> {
    /// Placeholder for `value`; the same value always maps to the same placeholder in a session.
    pub fn placeholder_for(&mut self, entity_type: &str, value: &str) -> DlpResult<String> {
        if value.len() > self.vault.cfg.max_value_bytes {
            return Err(DlpError::TooLarge("value too large for vault".into()));
        }
        let tag = self.vault.value_tag(value);
        let k = (entity_type.to_string(), tag);
        if let Some(p) = self.s.by_value.get(&k) {
            return Ok(p.clone());
        }
        if self.s.entries.len() >= self.vault.cfg.max_entries_per_session {
            return Err(DlpError::TooLarge("vault entry limit reached for session".into()));
        }
        let clean: String = entity_type.chars().map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '_' }).collect();
        let n = self.s.counters.entry(entity_type.to_string()).or_insert(0);
        *n += 1;
        let ph = if self.s.nonce_mode { format!("[{clean}_{n}#{}]", self.s.nonce) } else { format!("[{clean}_{n}]") };
        self.s.entries.insert(ph.clone(), Entry { entity_type: entity_type.to_string(), value: Zeroizing::new(value.to_string()) });
        self.s.by_value.insert(k, ph.clone());
        Ok(ph)
    }
    pub fn len(&self) -> usize {
        self.s.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.s.entries.is_empty()
    }
    pub fn age(&self) -> Duration {
        self.s.created.elapsed()
    }
    pub fn entity_type_of(&self, placeholder: &str) -> Option<&str> {
        self.s.entries.get(placeholder).map(|e| e.entity_type.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn caller(t: &str, s: &str, scopes: &[&str]) -> Caller {
        Caller::new(t, s, scopes)
    }
    #[test]
    fn roundtrip_and_same_value_same_placeholder() {
        let v = Vault::new(VaultConfig::default());
        let c = caller("t1", "u1", &["anonymize", "deanonymize"]);
        let (p1, p2, p3) = v
            .with_session(&c, "s1", true, None, |h| Ok((h.placeholder_for("PERSON", "张三")?, h.placeholder_for("PERSON", "张三")?, h.placeholder_for("PERSON", "李四")?)))
            .unwrap();
        assert_eq!(p1, "[PERSON_1]");
        assert_eq!(p1, p2);
        assert_eq!(p3, "[PERSON_2]");
        let r = v.deanonymize(&c, "s1", "已为[PERSON_1]整理，[PERSON_2]确认。").unwrap();
        assert_eq!(r.text, "已为张三整理，李四确认。");
        assert_eq!(r.restored, 2);
    }
    #[test]
    fn isolation_forgery_scope_expiry() {
        let v = Vault::new(VaultConfig::default());
        let a = caller("t1", "u1", &["deanonymize"]);
        v.with_session(&a, "s1", true, None, |h| h.placeholder_for("PHONE_NUMBER", "13800138000").map(|_| ())).unwrap();
        // other session of the same user: nothing to restore
        v.with_session(&a, "s2", true, None, |_| Ok(())).unwrap();
        let r = v.deanonymize(&a, "s2", "call [PHONE_NUMBER_1]").unwrap();
        assert_eq!(r.text, "call [PHONE_NUMBER_1]");
        assert_eq!(r.unknown_placeholders, 1);
        // other tenant, same session id
        let b = caller("t2", "u1", &["deanonymize"]);
        assert!(v.deanonymize(&b, "s1", "[PHONE_NUMBER_1]").is_err());
        // other subject, same tenant
        let c = caller("t1", "u2", &["deanonymize"]);
        assert!(v.deanonymize(&c, "s1", "[PHONE_NUMBER_1]").is_err());
        // missing scope
        let d = caller("t1", "u1", &["anonymize"]);
        assert!(matches!(v.deanonymize(&d, "s1", "x"), Err(DlpError::Forbidden(_))));
        // forged / fuzzy / case variants are never restored
        let r = v.deanonymize(&a, "s1", "[phone_number_1] [PHONE_NUMBER_01] [PHONE_NUMBER_9] [ PHONE_NUMBER_1 ]").unwrap();
        assert_eq!(r.restored, 0);
        // restored value that looks like a placeholder is not expanded again
        v.with_session(&a, "s3", true, None, |h| {
            h.placeholder_for("PERSON", "[PHONE_NUMBER_1]")?;
            h.placeholder_for("PHONE_NUMBER", "13900139000").map(|_| ())
        })
        .unwrap();
        let r = v.deanonymize(&a, "s3", "[PERSON_1]").unwrap();
        assert_eq!(r.text, "[PHONE_NUMBER_1]");
        // expiry
        v.expire_now(&a, "s1");
        assert!(matches!(v.deanonymize(&a, "s1", "[PHONE_NUMBER_1]"), Err(DlpError::NotFound(_))));
    }
    #[test]
    fn nonce_mode_blocks_plain_forgeries() {
        let v = Vault::new(VaultConfig { nonce_placeholders: true, ..Default::default() });
        let a = caller("t", "u", &["deanonymize"]);
        let ph = v.with_session(&a, "s", true, None, |h| h.placeholder_for("PERSON", "张三")).unwrap();
        assert!(ph.starts_with("[PERSON_1#"));
        assert_eq!(v.deanonymize(&a, "s", &ph).unwrap().text, "张三");
        assert_eq!(v.deanonymize(&a, "s", "[PERSON_1]").unwrap().restored, 0);
        assert_eq!(v.deanonymize(&a, "s", "[PERSON_1#000000]").unwrap().restored, 0);
    }
}
