use dlp_core::*;
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct NlpConfig {
    pub base_url: String,
    pub token: String,
    pub connect_timeout: Duration,
    pub default_timeout: Duration,
    pub max_idle_conns: usize,
    /// Consecutive failures before the circuit opens (fast-fail) and for how long.
    pub breaker_failures: u32,
    pub breaker_open: Duration,
}
impl Default for NlpConfig {
    fn default() -> Self {
        NlpConfig { base_url: "http://127.0.0.1:8791".into(), token: String::new(), connect_timeout: Duration::from_millis(800), default_timeout: Duration::from_secs(20), max_idle_conns: 64, breaker_failures: 3, breaker_open: Duration::from_secs(3) }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NlpKind {
    Presidio,
}
impl NlpKind {
    pub fn name(&self) -> &'static str {
        match self {
            NlpKind::Presidio => "presidio",
        }
    }
}

pub struct NlpClient {
    cfg: NlpConfig,
    agent: ureq::Agent,
    consecutive_failures: AtomicU32,
    open_until: Mutex<Option<Instant>>,
    status_cache: Mutex<Option<(Instant, Value)>>,
    pub requests: AtomicU64,
    pub failures: AtomicU64,
}

/// Raw per-text result of one backend.
#[derive(Debug, Default, Clone)]
pub struct BackendOut {
    pub per_text: Vec<Vec<Entity>>,
    pub state: String,
    pub message: String,
}

impl NlpClient {
    pub fn new(cfg: NlpConfig) -> Arc<NlpClient> {
        let agent = ureq::AgentBuilder::new().timeout_connect(cfg.connect_timeout).max_idle_connections(cfg.max_idle_conns).max_idle_connections_per_host(cfg.max_idle_conns).build();
        Arc::new(NlpClient { cfg, agent, consecutive_failures: AtomicU32::new(0), open_until: Mutex::new(None), status_cache: Mutex::new(None), requests: AtomicU64::new(0), failures: AtomicU64::new(0) })
    }

    fn breaker_is_open(&self) -> bool {
        let mut g = self.open_until.lock();
        match *g {
            Some(t) if Instant::now() < t => true,
            Some(_) => {
                *g = None; // half-open: allow one attempt
                false
            }
            None => false,
        }
    }
    fn note(&self, ok: bool) {
        if ok {
            self.consecutive_failures.store(0, Ordering::Relaxed);
        } else {
            self.failures.fetch_add(1, Ordering::Relaxed);
            if self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1 >= self.cfg.breaker_failures {
                *self.open_until.lock() = Some(Instant::now() + self.cfg.breaker_open);
            }
        }
    }

    /// One round trip analysing `texts` with the listed backends. Offsets in the reply are code
    /// points and are converted to UTF-8 byte offsets here.
    pub fn analyze(&self, texts: &[&str], kinds: &[NlpKind], language: &str, entities: &[String], threshold: f32, deadline: Option<Instant>) -> DlpResult<Vec<(NlpKind, BackendOut)>> {
        if self.breaker_is_open() {
            return Err(DlpError::DetectorUnavailable("nlp service circuit open (recent failures)".into()));
        }
        let timeout = match deadline {
            Some(d) => d.checked_duration_since(Instant::now()).filter(|x| !x.is_zero()).ok_or_else(|| DlpError::Timeout("deadline exceeded before nlp call".into()))?,
            None => self.cfg.default_timeout,
        };
        let body = json!({
            "texts": texts,
            "detectors": kinds.iter().map(|k| k.name()).collect::<Vec<_>>(),
            "language": language,
            "entities": entities,
            "threshold": threshold,
        });
        self.requests.fetch_add(1, Ordering::Relaxed);
        let mut req = self.agent.post(&format!("{}/v1/analyze", self.cfg.base_url)).timeout(timeout).set("Content-Type", "application/json");
        if !self.cfg.token.is_empty() {
            req = req.set("X-DLP-Token", &self.cfg.token);
        }
        let resp = match req.send_string(&body.to_string()) {
            Ok(r) => r,
            Err(ureq::Error::Status(503, _)) => {
                self.note(true); // service is alive, it is just shedding load
                return Err(DlpError::DetectorUnavailable("nlp service overloaded (back-pressure)".into()));
            }
            Err(ureq::Error::Status(code, _)) => {
                self.note(false);
                return Err(DlpError::DetectorUnavailable(format!("nlp service returned HTTP {code}")));
            }
            Err(e) => {
                self.note(false);
                let msg = e.to_string();
                return Err(if msg.contains("timed out") { DlpError::Timeout("nlp call timed out".into()) } else { DlpError::DetectorUnavailable(format!("nlp service unreachable: {}", msg.split(':').next().unwrap_or("io"))) });
            }
        };
        let v: Value = resp.into_string().map_err(|e| e.to_string()).and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string())).map_err(|e| {
            self.note(false);
            DlpError::DetectorUnavailable(format!("bad nlp response: {e}"))
        })?;
        self.note(true);
        let results = v["results"].as_array().ok_or_else(|| DlpError::DetectorUnavailable("nlp response without results".into()))?;
        let mut out = Vec::new();
        for kind in kinds {
            let name = kind.name();
            let st = &v["detectors"][name];
            let state = st["state"].as_str().unwrap_or("error").to_string();
            let message = st["message"].as_str().unwrap_or("").to_string();
            let mut per_text = Vec::with_capacity(texts.len());
            if state == "ready" {
                for (i, t) in texts.iter().enumerate() {
                    let arr = results.get(i).and_then(|r| r[name].as_array()).cloned().unwrap_or_default();
                    per_text.push(convert(t, &arr, name));
                }
            }
            out.push((kind.clone(), BackendOut { per_text, state, message }));
        }
        Ok(out)
    }

    pub fn status(&self) -> Option<Value> {
        {
            let c = self.status_cache.lock();
            if let Some((t, v)) = c.as_ref() {
                if t.elapsed() < Duration::from_secs(3) {
                    return Some(v.clone());
                }
            }
        }
        let mut req = self.agent.get(&format!("{}/status", self.cfg.base_url)).timeout(Duration::from_millis(1500));
        if !self.cfg.token.is_empty() {
            req = req.set("X-DLP-Token", &self.cfg.token);
        }
        let v: Option<Value> = req.call().ok().and_then(|r| r.into_string().ok()).and_then(|s| serde_json::from_str(&s).ok());
        *self.status_cache.lock() = v.clone().map(|v| (Instant::now(), v));
        v
    }
}

/// Entity vocabulary metadata for model outputs: (category, risk).
fn meta_for(entity_type: &str) -> (&'static str, RiskLevel) {
    match entity_type {
        "PERSON" => ("pii", RiskLevel::Medium),
        "ADDRESS" => ("contact", RiskLevel::Medium),
        "LOCATION" => ("contact", RiskLevel::Low),
        "PHONE_NUMBER" | "EMAIL_ADDRESS" => ("contact", RiskLevel::Medium),
        "ORGANIZATION" => ("business", RiskLevel::Low),
        "CREDIT_CARD" | "BANK_ACCOUNT" | "IBAN" | "CRYPTO_WALLET" => ("financial", RiskLevel::High),
        "PASSPORT" | "NATIONAL_ID" | "DRIVER_LICENSE" | "MEDICAL_LICENSE" => ("pii", RiskLevel::High),
        "DATE_OF_BIRTH" => ("pii", RiskLevel::Medium),
        _ => ("pii", RiskLevel::Medium),
    }
}

fn convert(text: &str, arr: &[Value], detector: &str) -> Vec<Entity> {
    let mut starts = Vec::with_capacity(arr.len() * 2);
    for a in arr {
        starts.push(a["start"].as_u64().unwrap_or(0) as usize);
        starts.push(a["end"].as_u64().unwrap_or(0) as usize);
    }
    let bytes = char_to_byte_offsets(text, &starts);
    let mut out = Vec::with_capacity(arr.len());
    for (i, a) in arr.iter().enumerate() {
        let (s, e) = (bytes[2 * i], bytes[2 * i + 1]);
        if e <= s {
            continue;
        }
        let et = a["entity_type"].as_str().unwrap_or("UNKNOWN");
        let recognizer = a["recognizer"].as_str().unwrap_or("");
        let (cat, risk) = meta_for(et);
        let mut ent = Entity::new(et, s, e, detector, &format!("{detector}:{recognizer}"));
        ent.confidence = a["score"].as_f64().unwrap_or(0.0) as f32;
        ent.risk_level = risk;
        ent.category = cat.to_string();
        // the service runs no statistical model: every hit is a pattern/checksum recognizer
        ent.evidence = Evidence::Pattern;
        if let Some(n) = a["notes"].as_object() {
            for (k, v) in n {
                if let Some(s) = v.as_str() {
                    ent.metadata.insert(k.clone(), s.to_string());
                }
            }
        }
        ent.metadata.insert("recognizer".into(), recognizer.to_string());
        out.push(ent);
    }
    out
}

pub struct NlpDetector {
    pub kind: NlpKind,
    pub client: Arc<NlpClient>,
    threshold: f32,
    metrics: MetricsRecorder,
    last_msg: Mutex<(DetectorState, String)>,
}

impl NlpDetector {
    pub fn new(kind: NlpKind, client: Arc<NlpClient>, threshold: f32) -> Self {
        NlpDetector { kind, client, threshold, metrics: MetricsRecorder::default(), last_msg: Mutex::new((DetectorState::Unavailable, "not contacted yet".into())) }
    }
    pub fn threshold(&self) -> f32 {
        self.threshold
    }
    pub fn record(&self, started: Instant, r: &DlpResult<Vec<Entity>>) {
        self.metrics.record(started, r);
        let mut l = self.last_msg.lock();
        *l = match r {
            Ok(_) => (DetectorState::Ready, String::new()),
            Err(e) => (DetectorState::Unavailable, e.to_string()),
        };
    }
}

impl Detector for NlpDetector {
    fn name(&self) -> &str {
        self.kind.name()
    }
    fn detect(&self, ctx: &DetectContext, text: &str) -> DlpResult<Vec<Entity>> {
        let mut r = self.detect_batch(ctx, &[text]);
        r.pop().unwrap_or_else(|| Err(DlpError::Internal("empty batch result".into())))
    }
    fn detect_batch(&self, ctx: &DetectContext, texts: &[&str]) -> Vec<DlpResult<Vec<Entity>>> {
        let t0 = Instant::now();
        let res = self.client.analyze(texts, std::slice::from_ref(&self.kind), &ctx.language, &ctx.entities, self.threshold, ctx.deadline);
        let outs: Vec<DlpResult<Vec<Entity>>> = match res {
            Ok(mut v) => {
                let (_, b) = v.remove(0);
                if b.state == "ready" {
                    b.per_text.into_iter().map(Ok).collect()
                } else {
                    let e = DlpError::DetectorUnavailable(format!("{} backend {}: {}", self.kind.name(), b.state, b.message));
                    texts.iter().map(|_| Err(e.clone())).collect()
                }
            }
            Err(e) => texts.iter().map(|_| Err(e.clone())).collect(),
        };
        for o in &outs {
            self.record(t0, o);
        }
        outs
    }
    fn status(&self) -> DetectorStatus {
        let remote = self.client.status();
        let name = self.kind.name();
        let (state, message, version) = match remote.as_ref().map(|v| &v[name]) {
            Some(v) if v["state"] == "ready" => (DetectorState::Ready, String::new(), v["version"].as_str().unwrap_or("").to_string()),
            Some(v) => (DetectorState::Unavailable, v["message"].as_str().unwrap_or(v["state"].as_str().unwrap_or("unavailable")).to_string(), String::new()),
            None => (DetectorState::Unavailable, "nlp service unreachable".into(), String::new()),
        };
        DetectorStatus { name: name.into(), state, message, version }
    }
    fn metrics(&self) -> DetectorMetrics {
        self.metrics.snapshot()
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
