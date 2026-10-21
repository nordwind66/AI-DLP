#![allow(non_camel_case_types)]
//! C ABI for the Unified AI DLP Engine (`libai_dlp.so` / `ai_dlp.dll`). See include/ai_dlp.h.
//!
//! Contract:
//!  * Data crosses the boundary as UTF-8 JSON with explicit lengths – no Rust or Python object is
//!    ever exposed. Request schema == HTTP API schema (docs/API.md).
//!  * Every function returns an `int` status; results are `dlp_result_t*` owned by the library until
//!    `dlp_free_result`. A result always carries valid JSON (success payload or `{"error":{...}}`).
//!  * Nothing unwinds across the boundary: every entry point runs under `catch_unwind` (DLP_ERR_PANIC).
//!  * A `dlp_engine_t*` is thread-safe; any number of threads may call concurrently.
//!    `dlp_destroy` must not race with other calls on the same handle.
//!  * The library is an in-process component: it trusts its host. Tenant/subject are supplied by the
//!    host in the request (`tenant_id`, `subject`) and all scopes are granted. Put an authenticating
//!    process (dlp-server) in front when callers are not trusted.
//!  * Pure-rule detection works without the NLP service. If `nlp_url` is configured, the Presidio
//!    rule recognizers run in the separate Python service; when it is down, results carry `degraded:true`.
use dlp_core::*;
use dlp_detectors::NlpConfig;
use dlp_engine::api_json::{run_body, Body};
use dlp_engine::*;
use serde_json::{json, Value};
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::Duration;

pub const DLP_ABI_VERSION: u32 = 1;

pub const DLP_OK: c_int = 0;
pub const DLP_ERR_INVALID_ARG: c_int = 1;
pub const DLP_ERR_INVALID_INPUT: c_int = 2;
pub const DLP_ERR_TOO_LARGE: c_int = 3;
pub const DLP_ERR_DETECTOR_UNAVAILABLE: c_int = 4;
pub const DLP_ERR_TIMEOUT: c_int = 5;
pub const DLP_ERR_RULES: c_int = 6;
pub const DLP_ERR_STORAGE: c_int = 7;
pub const DLP_ERR_POLICY: c_int = 8;
pub const DLP_ERR_VAULT: c_int = 9;
pub const DLP_ERR_FORBIDDEN: c_int = 10;
pub const DLP_ERR_NOT_FOUND: c_int = 11;
pub const DLP_ERR_PANIC: c_int = 98;
pub const DLP_ERR_INTERNAL: c_int = 99;

/// Library-owned result. `data` is NUL-terminated UTF-8 JSON (`len` excludes the NUL).
#[repr(C)]
pub struct dlp_result_t {
    pub code: c_int,
    pub data: *const c_char,
    pub len: usize,
    // private: owning buffer
    _buf: *mut Vec<u8>,
}

pub struct dlp_engine_t {
    engine: Arc<DlpEngine>,
}

pub struct dlp_stream_t {
    stream: EngineStream,
}

fn make_result(code: c_int, json: Value) -> *mut dlp_result_t {
    let mut v = serde_json::to_vec(&json).unwrap_or_else(|_| b"{\"error\":{\"code\":\"internal_error\",\"message\":\"serialization failed\"}}".to_vec());
    v.push(0);
    let len = v.len() - 1;
    let buf = Box::into_raw(Box::new(v));
    // SAFETY: buf was just created by Box::into_raw and is valid
    let data = unsafe { (*buf).as_ptr() as *const c_char };
    Box::into_raw(Box::new(dlp_result_t { code, data, len, _buf: buf }))
}

fn err_code(e: &DlpError) -> c_int {
    match e {
        DlpError::InvalidInput(_) => DLP_ERR_INVALID_INPUT,
        DlpError::TooLarge(_) => DLP_ERR_TOO_LARGE,
        DlpError::DetectorUnavailable(_) => DLP_ERR_DETECTOR_UNAVAILABLE,
        DlpError::Timeout(_) => DLP_ERR_TIMEOUT,
        DlpError::Rules(_) => DLP_ERR_RULES,
        DlpError::Storage(_) => DLP_ERR_STORAGE,
        DlpError::Policy(_) => DLP_ERR_POLICY,
        DlpError::Vault(_) => DLP_ERR_VAULT,
        DlpError::Forbidden(_) => DLP_ERR_FORBIDDEN,
        DlpError::NotFound(_) => DLP_ERR_NOT_FOUND,
        DlpError::Internal(_) => DLP_ERR_INTERNAL,
    }
}

fn fail(code: c_int, msg: &str) -> *mut dlp_result_t {
    make_result(code, json!({"error": {"code": code, "message": msg}}))
}

/// Run `f`, converting errors and panics into a result. Never unwinds.
fn guarded(out: *mut *mut dlp_result_t, f: impl FnOnce() -> Result<Value, (c_int, String)>) -> c_int {
    if out.is_null() {
        return DLP_ERR_INVALID_ARG;
    }
    let (code, res) = match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(v)) => (DLP_OK, make_result(DLP_OK, v)),
        Ok(Err((c, m))) => (c, fail(c, &m)),
        Err(_) => (DLP_ERR_PANIC, fail(DLP_ERR_PANIC, "internal panic (isolated)")),
    };
    // SAFETY: out checked non-null above
    unsafe { *out = res };
    code
}

fn input_str<'a>(p: *const c_char, len: usize) -> Result<&'a str, (c_int, String)> {
    if p.is_null() {
        return if len == 0 { Ok("") } else { Err((DLP_ERR_INVALID_ARG, "null pointer with non-zero length".into())) };
    }
    // SAFETY: caller guarantees p points to len readable bytes (documented contract)
    let bytes = unsafe { std::slice::from_raw_parts(p as *const u8, len) };
    std::str::from_utf8(bytes).map_err(|_| (DLP_ERR_INVALID_INPUT, "input is not valid UTF-8".into()))
}

fn engine_ref<'a>(e: *const dlp_engine_t) -> Result<&'a DlpEngine, (c_int, String)> {
    if e.is_null() {
        return Err((DLP_ERR_INVALID_ARG, "null engine handle".into()));
    }
    // SAFETY: non-null handle created by dlp_create and not yet destroyed (documented contract)
    Ok(unsafe { &(*e).engine })
}

fn caller_of(b: &Body, v: &Value) -> Caller {
    let subject = v.get("subject").and_then(|s| s.as_str()).unwrap_or("host");
    Caller::new(b.tenant_id.as_deref().unwrap_or("default"), subject, &["*"])
}

fn dlp_err((_, m): (c_int, String)) -> (c_int, String) {
    (DLP_ERR_INVALID_INPUT, m)
}

// ------------------------------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn dlp_abi_version() -> u32 {
    DLP_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn dlp_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// Create an engine. `config_json` may be empty/NULL (in-memory DB bootstrapped from `rules_dir` or ./rules).
#[no_mangle]
pub extern "C" fn dlp_create(config_json: *const c_char, config_len: usize, out_engine: *mut *mut dlp_engine_t, out_result: *mut *mut dlp_result_t) -> c_int {
    guarded(out_result, || {
        if out_engine.is_null() {
            return Err((DLP_ERR_INVALID_ARG, "out_engine is null".into()));
        }
        let text = input_str(config_json, config_len)?;
        let c: Value = if text.trim().is_empty() { json!({}) } else { serde_json::from_str(text).map_err(|e| (DLP_ERR_INVALID_INPUT, format!("config is not valid JSON: {e}")))? };
        let mut cfg = EngineConfig::default();
        cfg.db_path = c["db_path"].as_str().unwrap_or(":memory:").to_string();
        cfg.rules_dir = Some(c["rules_dir"].as_str().unwrap_or("rules").to_string());
        cfg.use_hyperscan = c["use_hyperscan"].as_bool().unwrap_or(true);
        if let Some(p) = c["default_policy"].as_str() {
            cfg.default_policy = p.to_string();
        }
        if let Some(n) = c["max_text_bytes"].as_u64() {
            cfg.limits.max_text_bytes = n as usize;
        }
        if let Some(n) = c["request_timeout_ms"].as_u64() {
            cfg.limits.request_timeout = Duration::from_millis(n);
        }
        if let Some(n) = c["vault_ttl_secs"].as_u64() {
            cfg.vault.ttl = Duration::from_secs(n);
        }
        cfg.vault.nonce_placeholders = c["nonce_placeholders"].as_bool().unwrap_or(false);
        if let Some(u) = c["nlp_url"].as_str() {
            cfg.nlp = Some(NlpConfig { base_url: u.trim_end_matches('/').to_string(), token: c["nlp_token"].as_str().unwrap_or("").to_string(), ..Default::default() });
        }
        let engine = DlpEngine::open(cfg).map_err(|e| (err_code(&e), e.to_string()))?;
        let caps = engine.capabilities();
        let h = Box::into_raw(Box::new(dlp_engine_t { engine }));
        // SAFETY: out_engine checked non-null
        unsafe { *out_engine = h };
        Ok(json!({"ok": true, "capabilities": caps}))
    })
}

#[no_mangle]
pub extern "C" fn dlp_destroy(engine: *mut dlp_engine_t) {
    if !engine.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| {
            // SAFETY: handle came from dlp_create; caller guarantees exclusive access here
            drop(unsafe { Box::from_raw(engine) });
        }));
    }
}

fn do_text(engine: *const dlp_engine_t, req: *const c_char, len: usize, out: *mut *mut dlp_result_t, forced: Option<Mode>) -> c_int {
    guarded(out, || {
        let e = engine_ref(engine)?;
        let text = input_str(req, len)?;
        let v: Value = serde_json::from_str(text).map_err(|e| (DLP_ERR_INVALID_INPUT, format!("request is not valid JSON: {e}")))?;
        let b: Body = serde_json::from_value(v.clone()).map_err(|e| (DLP_ERR_INVALID_INPUT, format!("bad request: {e}")))?;
        let caller = caller_of(&b, &v);
        run_body(e, &caller, &b, forced).map_err(|e| (err_code(&e), e.to_string()))
    })
}

/// Detect only (text never modified). Request: `{"text":..., "direction", "language", "policy_id", ...}`.
#[no_mangle]
pub extern "C" fn dlp_detect(engine: *const dlp_engine_t, request_json: *const c_char, request_len: usize, out: *mut *mut dlp_result_t) -> c_int {
    do_text(engine, request_json, request_len, out, Some(Mode::Detect))
}

/// Irreversible sanitization (MASK / REDACT / REPLACE; BLOCK reported in `decision`).
#[no_mangle]
pub extern "C" fn dlp_sanitize(engine: *const dlp_engine_t, request_json: *const c_char, request_len: usize, out: *mut *mut dlp_result_t) -> c_int {
    do_text(engine, request_json, request_len, out, Some(Mode::Sanitize))
}

/// Reversible anonymization through the session vault (`session_id` optional; returned in the result).
#[no_mangle]
pub extern "C" fn dlp_anonymize(engine: *const dlp_engine_t, request_json: *const c_char, request_len: usize, out: *mut *mut dlp_result_t) -> c_int {
    do_text(engine, request_json, request_len, out, Some(Mode::Anonymize))
}

/// Restore placeholders in a model response (after an independent response check).
/// Request: `{"session_id","text","tenant_id","subject","direction":"response","policy_id","check_response":true}`.
#[no_mangle]
pub extern "C" fn dlp_deanonymize(engine: *const dlp_engine_t, request_json: *const c_char, request_len: usize, out: *mut *mut dlp_result_t) -> c_int {
    guarded(out, || {
        let e = engine_ref(engine)?;
        let text = input_str(request_json, request_len)?;
        let v: Value = serde_json::from_str(text).map_err(|e| (DLP_ERR_INVALID_INPUT, format!("request is not valid JSON: {e}")))?;
        let sid = v["session_id"].as_str().ok_or((DLP_ERR_INVALID_INPUT, "session_id is required".into()))?;
        let t = v["text"].as_str().ok_or((DLP_ERR_INVALID_INPUT, "text is required".into()))?;
        let tenant = v["tenant_id"].as_str().unwrap_or("default");
        let subject = v["subject"].as_str().unwrap_or("host");
        let dir = v["direction"].as_str().and_then(Direction::parse).unwrap_or(Direction::Response);
        let caller = Caller::new(tenant, subject, &["*"]);
        let r = e.deanonymize(&caller, sid, t, dir, v["policy_id"].as_str(), v["check_response"].as_bool().unwrap_or(true)).map_err(|e| (err_code(&e), e.to_string()))?;
        serde_json::to_value(r).map_err(|e| (DLP_ERR_INTERNAL, e.to_string()))
    })
}

/// Validate -> compile -> atomically swap the rule set from SQLite. On failure the old set keeps serving.
#[no_mangle]
pub extern "C" fn dlp_reload_rules(engine: *const dlp_engine_t, out: *mut *mut dlp_result_t) -> c_int {
    guarded(out, || {
        let e = engine_ref(engine)?;
        let r = e.reload_rules(&Caller::local_admin()).map_err(|e| (err_code(&e), e.to_string()))?;
        serde_json::to_value(r).map_err(|e| (DLP_ERR_INTERNAL, e.to_string()))
    })
}

/// Engine / detector / ruleset status (never fails for a valid handle).
#[no_mangle]
pub extern "C" fn dlp_capabilities(engine: *const dlp_engine_t, out: *mut *mut dlp_result_t) -> c_int {
    guarded(out, || Ok(engine_ref(engine)?.capabilities()))
}

#[no_mangle]
pub extern "C" fn dlp_free_result(r: *mut dlp_result_t) {
    if r.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: r was produced by make_result; ownership returns here exactly once
        let boxed = unsafe { Box::from_raw(r) };
        drop(unsafe { Box::from_raw(boxed._buf) });
    }));
}

// ---------------------------------------------------------------------------------- streaming

/// Open a stream scanner. Options JSON: `{"policy_id","mode":"strict|window","anonymize":false,"session_id","tenant_id","subject"}`.
#[no_mangle]
pub extern "C" fn dlp_stream_open(engine: *const dlp_engine_t, options_json: *const c_char, options_len: usize, out_stream: *mut *mut dlp_stream_t, out: *mut *mut dlp_result_t) -> c_int {
    guarded(out, || {
        if out_stream.is_null() {
            return Err((DLP_ERR_INVALID_ARG, "out_stream is null".into()));
        }
        let e = engine_ref(engine)?;
        // the engine handle holds an Arc; we need our own clone for the stream
        let arc = unsafe { (*engine).engine.clone() };
        let text = input_str(options_json, options_len)?;
        let v: Value = if text.trim().is_empty() { json!({}) } else { serde_json::from_str(text).map_err(|e| (DLP_ERR_INVALID_INPUT, format!("options are not valid JSON: {e}")))? };
        let caller = Caller::new(v["tenant_id"].as_str().unwrap_or("default"), v["subject"].as_str().unwrap_or("host"), &["*"]);
        let opts = StreamOptions { policy_id: v["policy_id"].as_str().map(String::from), session_id: v["session_id"].as_str().map(String::from), anonymize: v["anonymize"].as_bool().unwrap_or(false), mode: v["mode"].as_str().map(String::from), max_buffer_bytes: v["max_buffer_bytes"].as_u64().map(|n| n as usize), nonce_placeholders: v["nonce_placeholders"].as_bool() };
        let _ = e;
        let s = arc.open_stream(&caller, &opts).map_err(|e| (err_code(&e), e.to_string()))?;
        let info = json!({"effective_mode": s.stats().effective_mode, "fallback_reason": s.stats().fallback_reason, "session_id": s.session_id});
        let h = Box::into_raw(Box::new(dlp_stream_t { stream: s }));
        // SAFETY: out_stream checked non-null
        unsafe { *out_stream = h };
        Ok(info)
    })
}

fn stream_out(s: &dlp_stream_t, bytes: Vec<u8>) -> Value {
    json!({"output": String::from_utf8_lossy(&bytes), "blocked": s.stream.is_blocked(), "stats": s.stream.stats()})
}

/// Feed upstream bytes; the result's `output` holds the bytes that may be forwarded now (possibly none).
#[no_mangle]
pub extern "C" fn dlp_stream_push(stream: *mut dlp_stream_t, data: *const u8, len: usize, out: *mut *mut dlp_result_t) -> c_int {
    guarded(out, || {
        if stream.is_null() || (data.is_null() && len > 0) {
            return Err((DLP_ERR_INVALID_ARG, "null stream or data".into()));
        }
        // SAFETY: handle from dlp_stream_open, used by one thread at a time (documented)
        let s = unsafe { &mut *stream };
        let bytes = if len == 0 { &[][..] } else { unsafe { std::slice::from_raw_parts(data, len) } };
        let o = s.stream.push(bytes);
        Ok(stream_out(s, o))
    })
}

/// Signal end of upstream; flushes everything still held after the final verdict.
#[no_mangle]
pub extern "C" fn dlp_stream_finish(stream: *mut dlp_stream_t, out: *mut *mut dlp_result_t) -> c_int {
    guarded(out, || {
        if stream.is_null() {
            return Err((DLP_ERR_INVALID_ARG, "null stream".into()));
        }
        let s = unsafe { &mut *stream };
        let o = s.stream.finish();
        Ok(stream_out(s, o))
    })
}

#[no_mangle]
pub extern "C" fn dlp_stream_close(stream: *mut dlp_stream_t) {
    if !stream.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { Box::from_raw(stream) })));
    }
}

#[allow(dead_code)]
fn _unused(_: (c_int, String)) -> (c_int, String) {
    dlp_err((0, String::new()))
}
