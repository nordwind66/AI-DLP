use crate::api::*;
use crate::gate::{Gate, GateError};
use arc_swap::ArcSwap;
use dlp_anonymizer::{execute, ExecItem, Vault, VaultConfig, VaultCtx};
use dlp_core::*;
use dlp_detectors::{NlpClient, NlpConfig, NlpDetector, NlpKind};
use dlp_policy::{FailMode, PolicyDef};
use dlp_rules::*;
use dlp_storage::Store;
use parking_lot::Mutex;
use rand::RngCore;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_text_bytes: usize,
    pub max_batch: usize,
    pub request_timeout: Duration,
    /// texts longer than this are not sent to the NLP service (treated as that detector failing)
    pub nlp_max_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Limits { max_text_bytes: 4 << 20, max_batch: 64, request_timeout: Duration::from_secs(30), nlp_max_bytes: 128 << 10 }
    }
}

#[derive(Clone)]
pub struct EngineConfig {
    pub db_path: String,
    /// Directory holding builtin.toml / gitleaks.toml used to bootstrap an EMPTY database.
    pub rules_dir: Option<String>,
    pub use_hyperscan: bool,
    pub nlp: Option<NlpConfig>,
    pub nlp_threshold: f32,
    pub nlp_max_inflight: usize,
    pub nlp_max_queue: usize,
    pub limits: Limits,
    pub vault: VaultConfig,
    pub merge: MergeConfig,
    pub default_policy: String,
    pub honor_inline_allow: bool,
    /// directions in which vault placeholders may be restored (never tool inputs by default)
    pub restore_directions: Vec<Direction>,
}
impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            db_path: "ai_dlp_rules.db".into(),
            rules_dir: None,
            use_hyperscan: true,
            nlp: None,
            nlp_threshold: 0.3,
            nlp_max_inflight: 4,
            nlp_max_queue: 64,
            limits: Limits::default(),
            vault: VaultConfig::default(),
            merge: MergeConfig::default(),
            default_policy: "default".into(),
            honor_inline_allow: false,
            restore_directions: vec![Direction::Response],
        }
    }
}

/// Metadata-only audit event (never contains text or values).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEvent {
    pub kind: &'static str,
    pub tenant: String,
    pub subject: String,
    pub policy_id: String,
    pub direction: &'static str,
    pub mode: &'static str,
    pub decision: &'static str,
    pub entity_counts: BTreeMap<String, usize>,
    pub degraded: bool,
    pub detectors_failed: Vec<String>,
    pub text_bytes: usize,
    pub ms: f64,
    pub ruleset_version: i64,
}

pub type AuditHook = Arc<dyn Fn(&AuditEvent) + Send + Sync>;

#[derive(Default)]
pub struct Counters {
    pub requests: AtomicU64,
    pub blocked: AtomicU64,
    pub modified: AtomicU64,
    pub degraded: AtomicU64,
    pub errors: AtomicU64,
    pub entities: AtomicU64,
    pub reloads_ok: AtomicU64,
    pub reloads_failed: AtomicU64,
    pub total_us: AtomicU64,
}

pub struct DlpEngine {
    pub cfg: EngineConfig,
    pub store: Arc<Store>,
    ruleset: RuleSetHandle,
    policies: ArcSwap<HashMap<String, Arc<PolicyDef>>>,
    detectors: HashMap<String, Arc<dyn Detector>>,
    nlp_client: Option<Arc<NlpClient>>,
    nlp_gate: Gate,
    pub vault: Arc<Vault>,
    reload_lock: Mutex<()>,
    last_change_counter: AtomicU64,
    audit: Mutex<Option<AuditHook>>,
    pub counters: Counters,
    pub started: Instant,
}

struct Prepared {
    policy: Arc<PolicyDef>,
    mode: Mode,
    ctx: DetectContext,
    enabled: Vec<String>,
    deadline: Instant,
}

#[derive(Default)]
struct DetectorRun {
    entities: Vec<Entity>,
    errors: HashMap<String, String>,
    ran: HashMap<String, f64>,
    skipped: HashMap<String, String>,
}

fn dir_str(d: Direction) -> &'static str {
    d.as_str()
}

impl DlpEngine {
    pub fn open(cfg: EngineConfig) -> DlpResult<Arc<DlpEngine>> {
        let store = Arc::new(if cfg.db_path == ":memory:" { Store::open_in_memory() } else { Store::open(&cfg.db_path) }.map_err(|e| DlpError::Storage(e.to_string()))?);
        Self::with_store(cfg, store)
    }

    pub fn with_store(cfg: EngineConfig, store: Arc<Store>) -> DlpResult<Arc<DlpEngine>> {
        let st = |e: dlp_storage::StoreError| DlpError::Storage(e.to_string());
        let mut def = store.load_ruleset_def().map_err(st)?;
        if def.rules.is_empty() {
            if let Some(dir) = &cfg.rules_dir {
                bootstrap(&store, dir)?;
                def = store.load_ruleset_def().map_err(st)?;
            }
        }
        let rs = RuleSet::compile(&def, &CompileOptions { use_hyperscan: cfg.use_hyperscan }).map_err(|errs| DlpError::Rules(errs.iter().take(5).map(|e| e.to_string()).collect::<Vec<_>>().join("; ")))?;
        let fp = rs.fingerprint.clone();
        let mut rs = rs;
        let version = store.publish_version(&def, &fp, "engine startup").map_err(st)?;
        rs.version = version;
        let handle = new_handle(rs);

        let mut detectors: HashMap<String, Arc<dyn Detector>> = HashMap::new();
        detectors.insert("regex".into(), Arc::new(RuleDetector::regex(handle.clone())));
        detectors.insert("hyperscan".into(), Arc::new(RuleDetector::hyperscan(handle.clone())));
        detectors.insert("secret".into(), Arc::new(RuleDetector::secret(handle.clone())));
        detectors.insert("dictionary".into(), Arc::new(RuleDetector::dictionary(handle.clone())));
        let nlp_client = cfg.nlp.clone().map(NlpClient::new);
        if let Some(c) = &nlp_client {
            detectors.insert("presidio".into(), Arc::new(NlpDetector::new(NlpKind::Presidio, c.clone(), cfg.nlp_threshold)));
        }
        let policies = load_policies(&store, &detectors)?;
        let counter = store.change_counter().map_err(st)?;
        Ok(Arc::new(DlpEngine {
            nlp_gate: Gate::new(cfg.nlp_max_inflight, cfg.nlp_max_queue),
            vault: Arc::new(Vault::new(cfg.vault.clone())),
            cfg,
            store,
            ruleset: handle,
            policies: ArcSwap::from_pointee(policies),
            detectors,
            nlp_client,
            reload_lock: Mutex::new(()),
            last_change_counter: AtomicU64::new(counter as u64),
            audit: Mutex::new(None),
            counters: Counters::default(),
            started: Instant::now(),
        }))
    }

    pub fn set_audit_hook(&self, h: AuditHook) {
        *self.audit.lock() = Some(h);
    }
    fn emit(&self, ev: AuditEvent) {
        if let Some(h) = self.audit.lock().clone() {
            h(&ev);
        }
    }

    pub fn ruleset(&self) -> Arc<RuleSet> {
        self.ruleset.load_full()
    }
    pub fn ruleset_handle(&self) -> RuleSetHandle {
        self.ruleset.clone()
    }
    pub fn policy(&self, id: &str) -> Option<Arc<PolicyDef>> {
        self.policies.load().get(id).cloned()
    }
    pub fn policy_ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.policies.load().keys().cloned().collect();
        v.sort();
        v
    }

    fn require(&self, caller: &Caller, scope: &str) -> DlpResult<()> {
        if caller.has_scope(scope) {
            Ok(())
        } else {
            Err(DlpError::Forbidden(format!("missing scope '{scope}'")))
        }
    }

    // ------------------------------------------------------------------ rules management
    /// Validate -> compile -> atomically swap. On any failure the previous rule set keeps serving.
    pub fn reload_rules(&self, caller: &Caller) -> DlpResult<ReloadReport> {
        self.require(caller, "rules:reload")?;
        self.reload_inner("reload_rules()")
    }

    fn reload_inner(&self, reason: &str) -> DlpResult<ReloadReport> {
        let _g = self.reload_lock.lock();
        let r = self.try_reload(reason);
        match &r {
            Ok(_) => self.counters.reloads_ok.fetch_add(1, Ordering::Relaxed),
            Err(_) => self.counters.reloads_failed.fetch_add(1, Ordering::Relaxed),
        };
        r
    }

    fn try_reload(&self, reason: &str) -> DlpResult<ReloadReport> {
        let st = |e: dlp_storage::StoreError| DlpError::Storage(e.to_string());
        let counter = self.store.change_counter().map_err(st)?;
        let def = self.store.load_ruleset_def().map_err(st)?;
        let rs = RuleSet::compile(&def, &CompileOptions { use_hyperscan: self.cfg.use_hyperscan }).map_err(|errs| {
            DlpError::Rules(format!("{} rule(s) failed validation, previous rule set kept: {}", errs.len(), errs.iter().take(5).map(|e| e.to_string()).collect::<Vec<_>>().join("; ")))
        })?;
        let policies = load_policies(&self.store, &self.detectors)?;
        let cur = self.ruleset.load();
        self.last_change_counter.store(counter as u64, Ordering::Relaxed);
        let policies_changed = {
            let old = self.policies.load();
            old.len() != policies.len() || policies.iter().any(|(k, v)| old.get(k).map(|o| serde_json::to_string(&**o).ok() != serde_json::to_string(&**v).ok()).unwrap_or(true))
        };
        if rs.fingerprint == cur.fingerprint && !policies_changed {
            return Ok(report(&cur, false, policies.len(), "no changes"));
        }
        let version = self.store.publish_version(&def, &rs.fingerprint, reason).map_err(st)?;
        let mut rs = rs;
        rs.version = version;
        let rep = report(&rs, true, policies.len(), "rule set swapped");
        self.ruleset.store(Arc::new(rs)); // atomic: in-flight scans keep their Arc<RuleSet>
        self.policies.store(Arc::new(policies));
        Ok(rep)
    }

    /// Reload only if something changed in the database since the last (re)load.
    pub fn reload_if_changed(&self) -> DlpResult<Option<ReloadReport>> {
        let c = self.store.change_counter().map_err(|e| DlpError::Storage(e.to_string()))? as u64;
        if c == self.last_change_counter.load(Ordering::Relaxed) {
            return Ok(None);
        }
        self.reload_inner("auto reload (database changed)").map(Some)
    }

    pub fn rollback_rules(&self, caller: &Caller, version: i64) -> DlpResult<ReloadReport> {
        self.require(caller, "rules:reload")?;
        let st = |e: dlp_storage::StoreError| DlpError::Storage(e.to_string());
        let _g = self.reload_lock.lock();
        // keep the live state restorable: snapshot what is in the tables right now
        let cur_def = self.store.load_ruleset_def().map_err(st)?;
        let cur_fp = {
            let mut c = cur_def.clone();
            c.version = 0;
            dlp_storage::sha256_hex(&serde_json::to_vec(&c).unwrap_or_default())
        };
        let pre = self.store.publish_version(&cur_def, &cur_fp, &format!("pre-rollback to v{version}")).map_err(st)?;
        self.store.restore_version(version).map_err(st)?;
        match self.try_reload(&format!("rollback to v{version}")) {
            Ok(r) => Ok(r),
            Err(e) => {
                // the restored snapshot does not compile: put the tables back
                let _ = self.store.restore_version(pre);
                Err(DlpError::Rules(format!("rollback to v{version} rejected, tables restored: {e}")))
            }
        }
    }

    // ------------------------------------------------------------------ detection
    fn prepare(&self, caller: &Caller, req: &DetectRequest) -> DlpResult<Prepared> {
        let mode = req.mode.unwrap_or(Mode::Detect);
        self.require(caller, match mode {
            Mode::Detect => "detect",
            Mode::Sanitize => "sanitize",
            Mode::Anonymize => "anonymize",
        })?;
        if req.reveal_values {
            self.require(caller, "debug:reveal")?;
        }
        if req.text.len() > self.cfg.limits.max_text_bytes {
            return Err(DlpError::TooLarge(format!("text of {} bytes exceeds limit {}", req.text.len(), self.cfg.limits.max_text_bytes)));
        }
        let pid = req.policy_id.clone().unwrap_or_else(|| self.cfg.default_policy.clone());
        let policy = self.policy(&pid).ok_or_else(|| DlpError::NotFound(format!("policy '{pid}'")))?;
        let mut enabled = req.detectors.clone().unwrap_or_else(|| policy.enabled_detectors.clone());
        // a caller may narrow the detector list but never remove mandatory ones
        for m in &policy.mandatory_detectors {
            if !enabled.contains(m) {
                enabled.push(m.clone());
            }
        }
        let deadline = Instant::now() + self.cfg.limits.request_timeout;
        let ctx = DetectContext { direction: req.direction, language: req.language.clone(), entities: req.entities.clone(), min_confidence: policy.min_confidence, deadline: Some(deadline), request_id: String::new(), exhaustive: req.exhaustive };
        Ok(Prepared { policy, mode, ctx, enabled, deadline })
    }

    fn rule_backend(&self) -> &'static str {
        if self.cfg.use_hyperscan && self.ruleset.load().hs_active() {
            "hyperscan"
        } else {
            "regex"
        }
    }

    fn run_rules(&self, prep: &Prepared, text: &str, run: &mut DetectorRun) {
        for name in &prep.enabled {
            let (key, label) = match name.as_str() {
                "regex" => (self.rule_backend(), "regex"),
                "hyperscan" => ("hyperscan", "hyperscan"),
                "secret" => ("secret", "secret"),
                "dictionary" => ("dictionary", "dictionary"),
                _ => continue,
            };
            let Some(det) = self.detectors.get(key) else { continue };
            let t0 = Instant::now();
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| det.detect(&prep.ctx, text))) {
                Ok(Ok(mut v)) => {
                    run.ran.insert(label.into(), t0.elapsed().as_secs_f64() * 1000.0);
                    run.entities.append(&mut v);
                }
                Ok(Err(e)) => {
                    run.errors.insert(label.into(), e.to_string());
                }
                Err(_) => {
                    run.errors.insert(label.into(), "detector panicked (isolated)".into());
                }
            }
        }
    }

    fn nlp_kinds(&self, prep: &Prepared) -> Vec<NlpKind> {
        let mut k = vec![];
        if prep.enabled.iter().any(|d| d == "presidio") {
            k.push(NlpKind::Presidio);
        }
        k
    }

    /// Run the NLP detectors for `texts` in one IPC round trip (behind the concurrency gate).
    fn run_nlp(&self, kinds: &[NlpKind], texts: &[&str], language: &str, entities: &[String], deadline: Instant) -> Result<Vec<(NlpKind, Vec<DlpResult<Vec<Entity>>>, f64)>, String> {
        let Some(client) = &self.nlp_client else { return Err("NLP service not configured".into()) };
        let _permit = self.nlp_gate.acquire(Some(deadline)).map_err(|e| match e {
            GateError::QueueFull => "NLP queue full (back-pressure)".to_string(),
            GateError::Timeout => "timed out waiting for an NLP slot".to_string(),
        })?;
        let t0 = Instant::now();
        let res = client.analyze(texts, kinds, language, entities, self.cfg.nlp_threshold, Some(deadline)).map_err(|e| e.to_string())?;
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        Ok(res
            .into_iter()
            .map(|(kind, out)| {
                let per: Vec<DlpResult<Vec<Entity>>> = if out.state == "ready" {
                    out.per_text.into_iter().map(Ok).collect()
                } else {
                    let e = DlpError::DetectorUnavailable(format!("{} {}: {}", kind.name(), out.state, out.message));
                    texts.iter().map(|_| Err(e.clone())).collect()
                };
                (kind, per, ms)
            })
            .collect())
    }

    pub fn process(&self, caller: &Caller, req: &DetectRequest) -> DlpResult<DetectResponse> {
        self.process_many(caller, std::slice::from_ref(req)).pop().unwrap_or_else(|| Err(DlpError::Internal("no result".into())))
    }

    /// Batch entry point. Rule detection runs in parallel across items; all NLP work of items that
    /// share (policy detectors, language, entity filter) goes out as ONE batched IPC call.
    pub fn process_many(&self, caller: &Caller, reqs: &[DetectRequest]) -> Vec<DlpResult<DetectResponse>> {
        if reqs.len() > self.cfg.limits.max_batch {
            let e = DlpError::TooLarge(format!("batch of {} exceeds limit {}", reqs.len(), self.cfg.limits.max_batch));
            return reqs.iter().map(|_| Err(e.clone())).collect();
        }
        let t_start = Instant::now();
        let prepared: Vec<DlpResult<Prepared>> = reqs.iter().map(|r| self.prepare(caller, r)).collect();
        let n = reqs.len();
        // Shield placeholders issued by the request's own vault session: detectors see a neutral filler of
        // identical byte length, so offsets stay valid and `[PERSON_1]` is never "detected" again.
        // Only EXACT issued placeholders are shielded: wrapping a secret in brackets cannot hide it.
        let mut shields: Vec<Vec<(usize, usize)>> = vec![Vec::new(); n];
        let mut det_texts: Vec<std::borrow::Cow<str>> = reqs.iter().map(|r| std::borrow::Cow::Borrowed(r.text.as_str())).collect();
        for (i, r) in reqs.iter().enumerate() {
            if prepared[i].is_err() {
                continue;
            }
            let Some(sid) = &r.session_id else { continue };
            if !r.text.contains('[') {
                continue;
            }
            if let Some(issued) = self.vault.issued(caller, sid) {
                let mut buf = r.text.clone().into_bytes();
                for m in dlp_anonymizer::placeholder_regex().find_iter(&r.text) {
                    if issued.contains(m.as_str()) {
                        shields[i].push((m.start(), m.end()));
                        buf[m.start()..m.end()].fill(b'_');
                    }
                }
                if !shields[i].is_empty() {
                    det_texts[i] = std::borrow::Cow::Owned(String::from_utf8(buf).unwrap_or_else(|_| r.text.clone()));
                }
            }
        }
        let mut runs: Vec<DetectorRun> = (0..n).map(|_| DetectorRun::default()).collect();

        // ---- group NLP work
        type GroupKey = (Vec<&'static str>, String, Vec<String>);
        let mut groups: HashMap<GroupKey, Vec<usize>> = HashMap::new();
        for (i, p) in prepared.iter().enumerate() {
            let Ok(p) = p else { continue };
            let kinds = self.nlp_kinds(p);
            if kinds.is_empty() {
                continue;
            }
            let text = det_texts[i].as_ref();
            let trivial = p.policy.nlp_trigger == "auto" && (text.chars().filter(|c| c.is_alphabetic()).count() < 6);
            if trivial {
                for k in &kinds {
                    runs[i].skipped.insert(k.name().into(), "skipped: trivial text (nlp_trigger=auto)".into());
                }
                continue;
            }
            if text.len() > self.cfg.limits.nlp_max_bytes {
                for k in &kinds {
                    runs[i].errors.insert(k.name().into(), format!("text of {} bytes exceeds nlp_max_bytes {}", text.len(), self.cfg.limits.nlp_max_bytes));
                }
                continue;
            }
            groups.entry((kinds.iter().map(|k| k.name()).collect(), p.ctx.language.clone(), p.ctx.entities.clone())).or_default().push(i);
        }

        let rule_results: Vec<Mutex<DetectorRun>> = (0..n).map(|_| Mutex::new(DetectorRun::default())).collect();
        let nlp_results: Mutex<Vec<(Vec<usize>, Vec<NlpKind>, Result<Vec<(NlpKind, Vec<DlpResult<Vec<Entity>>>, f64)>, String>)>> = Mutex::new(vec![]);
        let next_idx = std::sync::atomic::AtomicUsize::new(0);
        std::thread::scope(|sc| {
            // NLP groups run concurrently with rule detection
            for (key, idxs) in &groups {
                let kinds: Vec<NlpKind> = key.0.iter().filter(|k| **k == "presidio").map(|_| NlpKind::Presidio).collect();
                let texts: Vec<&str> = idxs.iter().map(|&i| det_texts[i].as_ref()).collect();
                let deadline = idxs.iter().filter_map(|&i| prepared[i].as_ref().ok().map(|p| p.deadline)).min().unwrap_or_else(|| Instant::now() + Duration::from_secs(10));
                let (lang, ents) = (key.1.clone(), key.2.clone());
                let nlp_results = &nlp_results;
                let idxs = idxs.clone();
                sc.spawn(move || {
                    let r = self.run_nlp(&kinds, &texts, &lang, &ents, deadline);
                    nlp_results.lock().push((idxs, kinds, r));
                });
            }
            // rule detection: one worker per chunk of items
            let workers = std::thread::available_parallelism().map(|x| x.get()).unwrap_or(2).min(n).max(1);
            let next = &next_idx;
            let rule_results = &rule_results;
            let prepared = &prepared;
            let det_texts = &det_texts;
            for _ in 0..workers {
                let work = move || loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= n {
                        break;
                    }
                    if let Ok(p) = &prepared[i] {
                        let mut run = DetectorRun::default();
                        self.run_rules(p, det_texts[i].as_ref(), &mut run);
                        *rule_results[i].lock() = run;
                    }
                };
                if workers == 1 {
                    work();
                } else {
                    sc.spawn(work);
                }
            }
        });
        for (i, m) in rule_results.into_iter().enumerate() {
            let r = m.into_inner();
            runs[i].entities.extend(r.entities);
            runs[i].errors.extend(r.errors);
            runs[i].ran.extend(r.ran);
        }
        for (idxs, kinds, res) in nlp_results.into_inner() {
            match res {
                Err(msg) => {
                    for &i in &idxs {
                        for k in &kinds {
                            runs[i].errors.insert(k.name().into(), msg.clone());
                        }
                    }
                }
                Ok(per_kind) => {
                    for (kind, per_text, ms) in per_kind {
                        for (slot, &i) in idxs.iter().enumerate() {
                            match &per_text[slot] {
                                Ok(v) => {
                                    runs[i].ran.insert(kind.name().into(), ms / idxs.len() as f64);
                                    runs[i].entities.extend(v.iter().cloned());
                                }
                                Err(e) => {
                                    runs[i].errors.insert(kind.name().into(), e.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        // ---- finalize each request
        let ms_all = t_start.elapsed().as_secs_f64() * 1000.0;
        let mut out = Vec::with_capacity(n);
        for (i, p) in prepared.into_iter().enumerate() {
            let r = p.and_then(|p| self.finalize(caller, &reqs[i], &p, std::mem::take(&mut runs[i]), ms_all, &shields[i]));
            if r.is_err() {
                self.counters.errors.fetch_add(1, Ordering::Relaxed);
            }
            out.push(r);
        }
        out
    }

    fn finalize(&self, caller: &Caller, req: &DetectRequest, p: &Prepared, run: DetectorRun, ms: f64, shield: &[(usize, usize)]) -> DlpResult<DetectResponse> {
        let text = req.text.as_str();
        let rs = self.ruleset.load();
        let mut warnings: Vec<String> = Vec::new();
        // ---- detector status / degradation
        // Logical detectors: regex (PII pattern rules; backend = hyperscan prefilter or portable regex),
        // secret, dictionary, presidio. "hyperscan" is listed only if a policy names it.
        let mut reports: Vec<DetectorReport> = Vec::new();
        let mut names: Vec<&str> = vec!["regex", "secret", "dictionary", "presidio"];
        if p.enabled.iter().any(|e| e == "hyperscan") {
            names.push("hyperscan");
        }
        let mut blocked_reason: Option<String> = None;
        let mut degraded = false;
        let mut failed: Vec<String> = vec![];
        for name in names {
            let enabled = p.enabled.iter().any(|e| e == name);
            let det = if name == "regex" { self.detectors.get(self.rule_backend()) } else { self.detectors.get(name) };
            let (state, mut message, backend) = match det {
                Some(d) => {
                    let s = d.status();
                    (s.state, s.message, if name == "regex" { Some(d.name().to_string()) } else { None })
                }
                None => (DetectorState::Unavailable, "detector not configured".to_string(), None),
            };
            if let Some(b) = backend {
                message = format!("backend={b}; {message}");
            }
            let mandatory = p.policy.is_mandatory(name);
            let ran = run.ran.contains_key(name);
            let error = run.errors.get(name).cloned().or_else(|| {
                if enabled && !ran && !run.skipped.contains_key(name) {
                    Some(if det.is_some() { "did not run".to_string() } else { "detector not configured".to_string() })
                } else {
                    None
                }
            });
            if enabled && error.is_some() {
                degraded = true;
                failed.push(name.to_string());
                warnings.push(format!("detector '{name}' unavailable for this request: {}", error.clone().unwrap_or_default()));
                if mandatory {
                    match p.policy.fail_mode {
                        FailMode::FailClosed => {
                            blocked_reason.get_or_insert_with(|| format!("mandatory detector '{name}' unavailable (fail_closed)"));
                        }
                        FailMode::FailOpenWithAudit => warnings.push(format!("fail_open_with_audit: continuing without mandatory detector '{name}'")),
                    }
                }
            }
            if let Some(sk) = run.skipped.get(name) {
                message = sk.clone();
            }
            reports.push(DetectorReport { name: name.to_string(), state, message, enabled, ran, error, mandatory, ms: run.ran.get(name).copied().unwrap_or(0.0) });
        }

        // ---- merge + policy
        let mut cands = run.entities;
        if !shield.is_empty() {
            // anything that touches a shielded placeholder was produced from filler text
            cands.retain(|e| !shield.iter().any(|&(a, b)| e.start < b && a < e.end));
        }
        if !req.entities.is_empty() {
            cands.retain(|e| req.entities.contains(&e.entity_type));
        }
        let merged = merge_entities(cands, &self.cfg.merge);
        let mut kept: Vec<(Entity, dlp_policy::Decision)> = Vec::with_capacity(merged.len());
        let mut suppressed = 0usize;
        for mut e in merged {
            let d = p.policy.decide(&e, req.direction);
            if d.suppressed {
                suppressed += 1;
                continue;
            }
            let mut d = d;
            if let Some(o) = req.action_overrides.get(&e.entity_type) {
                if strictness(*o) >= strictness(d.action) {
                    d.action = *o;
                }
            }
            e.action = d.action;
            kept.push((e, d));
        }
        // LLM Guard: merge same-type entities separated only by whitespace (decide actions first, then merge)
        {
            let (ents, decs): (Vec<Entity>, Vec<dlp_policy::Decision>) = kept.into_iter().unzip();
            let n0 = ents.len();
            let merged_ents = merge_adjacent_same_type(ents, text);
            if merged_ents.len() == n0 {
                kept = merged_ents.into_iter().zip(decs).collect();
            } else {
                // re-decide for the merged spans (same type => same rule outcome)
                kept = merged_ents
                    .into_iter()
                    .map(|mut e| {
                        let mut d = p.policy.decide(&e, req.direction);
                        if let Some(o) = req.action_overrides.get(&e.entity_type) {
                            if strictness(*o) >= strictness(d.action) {
                                d.action = *o;
                            }
                        }
                        e.action = d.action;
                        (e, d)
                    })
                    .collect();
            }
        }
        // defensive: executor needs strictly non-overlapping spans
        let mut last_end = 0usize;
        kept.retain(|(e, _)| {
            let ok = e.start >= last_end;
            if ok {
                last_end = e.end;
            }
            ok
        });
        let mut verdict = if kept.iter().any(|(_, d)| d.action == Action::Block) { Verdict::Blocked } else if kept.iter().any(|(e, _)| e.action != Action::Pass) { Verdict::Modified } else { Verdict::Allow };
        if let Some(r) = &blocked_reason {
            verdict = Verdict::Blocked;
            let _ = r;
        } else if verdict == Verdict::Blocked {
            blocked_reason = kept.iter().find(|(_, d)| d.action == Action::Block).map(|(e, _)| format!("policy BLOCK on {} ({})", e.entity_type, e.rule_id));
        }

        // ---- execute
        let mut sanitized: Option<String> = None;
        let mut replacements: HashMap<usize, (Action, String)> = HashMap::new();
        let mut session_out = req.session_id.clone();
        if verdict != Verdict::Blocked && p.mode != Mode::Detect {
            let mut items: Vec<ExecItem> = Vec::new();
            let mut idx_map: Vec<usize> = Vec::new();
            for (i, (e, d)) in kept.iter().enumerate() {
                let mut action = d.action;
                if p.mode == Mode::Sanitize && action == Action::Anonymize {
                    action = Action::Redact;
                }
                if action.modifies() {
                    items.push(ExecItem { entity: e, action, replacement: d.replacement.as_deref() });
                    idx_map.push(i);
                }
            }
            let sid;
            let vctx = if p.mode == Mode::Anonymize {
                sid = match &req.session_id {
                    Some(s) => s.clone(),
                    None => {
                        let mut b = [0u8; 16];
                        rand::thread_rng().fill_bytes(&mut b);
                        hex::encode(b) // unguessable vault id
                    }
                };
                session_out = Some(sid.clone());
                Some(VaultCtx { vault: &self.vault, caller, session_id: &sid, nonce_mode: req.nonce_placeholders })
            } else {
                None
            };
            if let Some(v) = &vctx {
                // anonymize mode always establishes the session (even with nothing to replace) so the
                // later restore call finds it; ownership/TTL are fixed at this point
                v.vault.with_session(v.caller, v.session_id, true, v.nonce_mode, |_| Ok(()))?;
            }
            let outcome = execute(text, &items, vctx.as_ref())?;
            for r in &outcome.replacements {
                replacements.insert(idx_map[r.entity_index], (r.applied, outcome.text[r.out_start..r.out_end].to_string()));
            }
            sanitized = Some(outcome.text);
        }

        // ---- render
        let offs = if kept.is_empty() { None } else { Some(OffsetMap::new(text)) };
        let spans: Vec<(usize, usize, &str)> = kept.iter().map(|(e, _)| (e.start, e.end, e.entity_type.as_str())).collect();
        let mut ents_out = Vec::with_capacity(kept.len());
        for (i, (e, _)) in kept.iter().enumerate() {
            let om = offs.as_ref().unwrap();
            let (applied, repl) = match replacements.get(&i) {
                Some((a, r)) => (*a, Some(r.clone())),
                None => (Action::Pass, None),
            };
            let mut md = e.metadata.clone();
            md.insert("evidence".into(), format!("{:?}", e.evidence).to_lowercase());
            md.insert("category".into(), e.category.clone());
            ents_out.push(EntityOut {
                entity_type: e.entity_type.clone(),
                start: om.char_offset(e.start),
                end: om.char_offset(e.end),
                byte_start: e.start,
                byte_end: e.end,
                confidence: (e.confidence * 1000.0).round() / 1000.0,
                risk_level: e.risk_level,
                detector: e.detector.clone(),
                rule_id: e.rule_id.clone(),
                action: e.action,
                applied_action: applied,
                context: build_context(text, i, &spans),
                metadata: md,
                value: if req.reveal_values { Some(text[e.start..e.end].to_string()) } else { None },
                replacement: repl,
            });
        }

        let ms_total = ms;
        if degraded {
            self.counters.degraded.fetch_add(1, Ordering::Relaxed);
        }
        self.counters.requests.fetch_add(1, Ordering::Relaxed);
        self.counters.entities.fetch_add(ents_out.len() as u64, Ordering::Relaxed);
        self.counters.total_us.fetch_add((ms_total * 1000.0) as u64, Ordering::Relaxed);
        match verdict {
            Verdict::Blocked => self.counters.blocked.fetch_add(1, Ordering::Relaxed),
            Verdict::Modified => self.counters.modified.fetch_add(1, Ordering::Relaxed),
            Verdict::Allow => 0,
        };
        let mut counts = BTreeMap::new();
        for e in &ents_out {
            *counts.entry(e.entity_type.clone()).or_insert(0) += 1;
        }
        self.emit(AuditEvent {
            kind: "detect",
            tenant: caller.tenant_id.clone(),
            subject: caller.subject.clone(),
            policy_id: p.policy.id.clone(),
            direction: dir_str(req.direction),
            mode: match p.mode {
                Mode::Detect => "detect",
                Mode::Sanitize => "sanitize",
                Mode::Anonymize => "anonymize",
            },
            decision: match verdict {
                Verdict::Allow => "allow",
                Verdict::Modified => "modified",
                Verdict::Blocked => "blocked",
            },
            entity_counts: counts,
            degraded,
            detectors_failed: failed,
            text_bytes: text.len(),
            ms: ms_total,
            ruleset_version: rs.version,
        });
        let actions_summary = {
            let mut a: Vec<Action> = ents_out.iter().map(|e| e.action).collect();
            a.sort();
            a.dedup();
            a
        };
        Ok(DetectResponse {
            decision: verdict,
            blocked_reason,
            entities: ents_out,
            sanitized_text: if verdict == Verdict::Blocked { None } else { sanitized },
            detector_status: reports,
            degraded,
            warnings,
            policy_id: p.policy.id.clone(),
            ruleset_version: rs.version,
            direction: req.direction,
            mode: p.mode,
            session_id: session_out,
            actions: actions_summary,
            suppressed_low_confidence: suppressed,
            processing_time_ms: (ms_total * 1000.0).round() / 1000.0,
        })
    }

    // ------------------------------------------------------------------ vault
    /// Restore placeholders in a model response.
    /// Order is fixed: (1) permission + direction + session ownership, (2) independent response
    /// detection under the response policy, (3) restore on the *sanitized* text. A blocked response
    /// is never restored.
    pub fn deanonymize(&self, caller: &Caller, session_id: &str, text: &str, direction: Direction, policy_id: Option<&str>, check_response: bool) -> DlpResult<DeanonymizeOut> {
        self.require(caller, "deanonymize")?;
        if !self.cfg.restore_directions.contains(&direction) {
            return Err(DlpError::Forbidden(format!("restoring placeholders is not allowed for direction '{}'", direction.as_str())));
        }
        if !check_response {
            self.require(caller, "deanonymize:skip_check")?;
        }
        // (1) session must exist and belong to the caller before any work is done
        self.vault.with_session(caller, session_id, false, None, |_| Ok(()))?;
        let mut checked: Option<DetectResponse> = None;
        let mut subject = text.to_string();
        if check_response {
            let mut r = DetectRequest::new(text);
            r.direction = direction;
            r.policy_id = policy_id.map(String::from);
            r.mode = Some(Mode::Sanitize);
            r.session_id = Some(session_id.to_string());
            let mut c = caller.clone();
            for s in ["sanitize"] {
                if !c.has_scope(s) {
                    c.scopes.push(s.into());
                }
            }
            let resp = self.process(&c, &r)?;
            if resp.decision == Verdict::Blocked {
                return Err(DlpError::Forbidden(format!("response blocked by policy, nothing restored: {}", resp.blocked_reason.clone().unwrap_or_default())));
            }
            subject = resp.sanitized_text.clone().unwrap_or_else(|| text.to_string());
            checked = Some(resp);
        }
        let r = self.vault.deanonymize(caller, session_id, &subject)?;
        Ok(DeanonymizeOut { text: r.text, restored: r.restored, unknown_placeholders: r.unknown_placeholders, response_check: checked })
    }

    // ------------------------------------------------------------------ introspection
    pub fn detector_statuses(&self) -> Vec<DetectorStatus> {
        let mut v: Vec<DetectorStatus> = self.detectors.values().map(|d| d.status()).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }
    pub fn detector_metrics(&self) -> Vec<(String, DetectorMetrics)> {
        let mut v: Vec<(String, DetectorMetrics)> = self.detectors.iter().map(|(k, d)| (k.clone(), d.metrics())).collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }
    pub fn nlp_status(&self) -> Option<serde_json::Value> {
        self.nlp_client.as_ref().and_then(|c| c.status())
    }

    pub fn capabilities(&self) -> serde_json::Value {
        let rs = self.ruleset.load();
        let mut types: Vec<String> = rs.rules_iter().map(|r| r.entity_type.clone()).collect();
        types.sort();
        types.dedup();
        let statuses = self.detector_statuses();
        let nlp_ok = statuses.iter().filter(|s| s.name == "presidio").all(|s| s.state == DetectorState::Ready);
        serde_json::json!({
            "engine_version": env!("CARGO_PKG_VERSION"),
            "ruleset": { "version": rs.version, "rules_enabled": rs.rule_count(), "fingerprint": rs.fingerprint, "hyperscan_active": rs.hs_active(), "hyperscan_version": rs.report.hs_version },
            "detectors": statuses,
            "full_capability": nlp_ok && self.nlp_client.is_some(),
            "note": "full_capability=false means NLP (Presidio rule-recognizer) detector are not all ready; rule-based detection still works and responses carry degraded=true when an enabled detector could not run",
            "entity_types": types,
            "actions": ["PASS","AUDIT","MASK","REDACT","REPLACE","ANONYMIZE","BLOCK"],
            "directions": ["request","response","tool_input","tool_output"],
            "modes": ["detect","sanitize","anonymize"],
            "policies": self.policy_ids(),
            "protocols": ["openai.chat.completions","openai.responses","anthropic.messages","json","text"],
            "stream_modes": ["strict","window"],
            "limits": { "max_text_bytes": self.cfg.limits.max_text_bytes, "max_batch": self.cfg.limits.max_batch, "request_timeout_ms": self.cfg.limits.request_timeout.as_millis() as u64, "nlp_max_bytes": self.cfg.limits.nlp_max_bytes },
            "vault": { "ttl_seconds": self.cfg.vault.ttl.as_secs(), "nonce_placeholders": self.cfg.vault.nonce_placeholders, "persistence": "memory-only" },
        })
    }
}

/// Ordering used for caller overrides: reversible anonymization is weaker than irreversible redaction.
fn strictness(a: Action) -> u8 {
    match a {
        Action::Pass => 0,
        Action::Audit => 1,
        Action::Anonymize => 2,
        Action::Mask => 3,
        Action::Replace | Action::Redact => 4,
        Action::Block => 5,
    }
}

fn report(rs: &RuleSet, changed: bool, policies: usize, msg: &str) -> ReloadReport {
    ReloadReport {
        changed,
        ruleset_version: rs.version,
        rules_enabled: rs.rule_count(),
        fingerprint: rs.fingerprint.clone(),
        hyperscan_active: rs.hs_active(),
        hyperscan_rejected_rules: rs.report.hs_failed.len(),
        path_only_skipped: rs.report.path_only_skipped.clone(),
        policies,
        compile_ms: rs.report.compile_ms,
        message: msg.to_string(),
    }
}

fn load_policies(store: &Store, detectors: &HashMap<String, Arc<dyn Detector>>) -> DlpResult<HashMap<String, Arc<PolicyDef>>> {
    let list = store.load_policies().map_err(|e| DlpError::Policy(e.to_string()))?;
    let mut m = HashMap::new();
    for p in list {
        // validate: references to unknown detectors are configuration errors, not silent no-ops
        for d in p.enabled_detectors.iter().chain(p.mandatory_detectors.iter()) {
            let known = matches!(d.as_str(), "regex" | "hyperscan" | "secret" | "dictionary" | "presidio");
            if !known {
                return Err(DlpError::Policy(format!("policy '{}' references unknown detector '{d}'", p.id)));
            }
        }
        let _ = detectors;
        m.insert(p.id.clone(), Arc::new(p));
    }
    Ok(m)
}

/// Import builtin.toml (+ gitleaks.toml when present) into an empty database.
pub fn bootstrap(store: &Store, rules_dir: &str) -> DlpResult<()> {
    let st = |e: dlp_storage::StoreError| DlpError::Storage(e.to_string());
    let gl = std::path::Path::new(rules_dir).join("gitleaks.toml");
    if gl.exists() {
        let text = std::fs::read_to_string(&gl).map_err(|e| DlpError::Storage(e.to_string()))?;
        dlp_storage::gitleaks::import_gitleaks_toml(store, &text, &dlp_storage::gitleaks::ImportMeta { source_version: "bundled".into(), source_commit: String::new() }).map_err(st)?;
    }
    let b = std::path::Path::new(rules_dir).join("builtin.toml");
    let text = std::fs::read_to_string(&b).map_err(|e| DlpError::Storage(format!("{}: {e}", b.display())))?;
    dlp_storage::builtin::import_builtin_toml(store, &text).map_err(st)?;
    Ok(())
}

/// Context snippet: ±24 bytes around entity `idx`, every detected span replaced by `[TYPE]`,
/// long digit runs elsewhere blurred. Never contains a detected value.
fn build_context(text: &str, idx: usize, spans: &[(usize, usize, &str)]) -> String {
    const W: usize = 24;
    let (s, e, _) = spans[idx];
    let lo = floor_char_boundary(text, s.saturating_sub(W));
    let hi = ceil_char_boundary(text, (e + W).min(text.len()));
    let mut out = String::new();
    let mut cur = lo;
    if lo > 0 {
        out.push('…');
    }
    for &(ss, ee, t) in spans.iter().filter(|(ss, ee, _)| *ss < hi && *ee > lo) {
        if ss > cur {
            out.push_str(&text[cur..ss.max(lo)]);
        }
        out.push_str(&format!("[{t}]"));
        cur = ee.min(hi).max(cur);
    }
    if cur < hi {
        out.push_str(&text[cur..hi]);
    }
    if hi < text.len() {
        out.push('…');
    }
    // blur residual digit runs and control characters
    let mut res = String::with_capacity(out.len());
    let mut run = 0;
    let chars: Vec<char> = out.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i].is_ascii_digit() {
            let j = chars[i..].iter().position(|c| !c.is_ascii_digit()).map(|p| i + p).unwrap_or(chars.len());
            if j - i >= 6 {
                res.extend(std::iter::repeat('#').take(j - i));
            } else {
                res.extend(&chars[i..j]);
            }
            i = j;
            run += 1;
            continue;
        }
        res.push(if chars[i].is_control() { ' ' } else { chars[i] });
        i += 1;
    }
    let _ = run;
    res
}
