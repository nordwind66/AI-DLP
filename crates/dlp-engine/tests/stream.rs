mod common;
use common::*;
use dlp_core::*;
use dlp_engine::*;
use serde_json::{json, Value};
use std::sync::Arc;

fn sse(data: &str) -> String {
    format!("data: {data}\n\n")
}
fn openai_chunk(content: &str) -> String {
    sse(&json!({"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":content},"finish_reason":null}]}).to_string())
}
fn openai_finish() -> String {
    sse(&json!({"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}).to_string()) + &sse("[DONE]")
}
/// concatenated delta.content of an OpenAI SSE byte stream
fn openai_text(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    for block in s.split("\n\n") {
        if let Some(d) = block.lines().find_map(|l| l.strip_prefix("data: ")) {
            if let Ok(v) = serde_json::from_str::<Value>(d) {
                if let Some(t) = v.pointer("/choices/0/delta/content").and_then(|t| t.as_str()) {
                    out.push_str(t);
                }
            }
        }
    }
    out
}

fn open(e: &Arc<DlpEngine>, policy: &str, mode: Option<&str>) -> EngineStream {
    e.open_stream(&admin(), &StreamOptions { policy_id: Some(policy.into()), mode: mode.map(String::from), ..Default::default() }).unwrap()
}

#[test]
fn scenario_f_phone_split_across_chunks_strict_releases_nothing_early() {
    let e = engine();
    let mut st = open(&e, "default", Some("strict"));
    let mut early = Vec::new();
    for part in ["请拨打 ", "138", "0013", "8000", " 联系我"] {
        early.extend(st.push(openai_chunk(part).as_bytes()));
    }
    assert!(early.is_empty(), "strict mode must not release ANY byte before the verdict, got {:?}", String::from_utf8_lossy(&early));
    let mut out = st.push(openai_finish().as_bytes());
    out.extend(st.finish());
    let text = openai_text(&out);
    assert_eq!(text, "请拨打 138****8000 联系我");
    assert!(!String::from_utf8_lossy(&out).contains("13800138000"));
    assert!(String::from_utf8_lossy(&out).contains("[DONE]"));
    assert_eq!(st.stats().effective_mode, "strict");
    assert_eq!(st.stats().entity_counts.get("PHONE_NUMBER"), Some(&1));
    // every emitted event is still valid JSON of the same shape (empty deltas allowed)
    for block in String::from_utf8_lossy(&out).split("\n\n").filter(|b| !b.is_empty() && !b.contains("[DONE]")) {
        let v: Value = serde_json::from_str(block.strip_prefix("data: ").unwrap()).unwrap();
        assert_eq!(v["id"], "c1");
    }
}

#[test]
fn byte_by_byte_crlf_and_multibyte() {
    let e = engine();
    let mut st = open(&e, "default", None);
    let raw = (openai_chunk("联系 138") + &openai_chunk("0013") + &openai_chunk("8000，谢谢") + &openai_finish()).replace('\n', "\r\n");
    let mut out = Vec::new();
    for b in raw.as_bytes() {
        out.extend(st.push(&[*b]));
    }
    out.extend(st.finish());
    assert_eq!(openai_text(&out), "联系 138****8000，谢谢");
}

#[test]
fn private_key_stream_is_redacted_not_refused() {
    let e = engine();
    let mut st = open(&e, "default", None);
    let mut early = Vec::new();
    early.extend(st.push(openai_chunk("Here is the key:\n").as_bytes()));
    for line in FAKE_PEM.lines() {
        early.extend(st.push(openai_chunk(&format!("{line}\n")).as_bytes()));
    }
    assert!(early.is_empty(), "strict mode releases nothing before the verdict");
    let mut out = st.push(openai_finish().as_bytes());
    out.extend(st.finish());
    assert!(!st.is_blocked());
    let t = openai_text(&out);
    assert_eq!(t, "Here is the key:\n[REDACTED_PRIVATE_KEY]\n");
    let s = String::from_utf8_lossy(&out);
    assert!(!s.contains("MIIEow") && !s.contains("BEGIN RSA") && s.contains("[DONE]"));
    // opt-in blocking policy
    let mut st = open(&e, "block-secrets", None);
    for line in FAKE_PEM.lines() {
        st.push(openai_chunk(&format!("{line}\n")).as_bytes());
    }
    let mut out = st.push(openai_finish().as_bytes());
    out.extend(st.finish());
    assert!(st.is_blocked() && String::from_utf8_lossy(&out).contains("dlp_blocked") && !String::from_utf8_lossy(&out).contains("MIIEow"));
}

#[test]
fn anthropic_stream_key_split_and_signed_thinking() {
    let e = engine();
    let ev = |t: &str, d: Value| format!("event: {t}\ndata: {}\n\n", json!({"type": t, "index": 0, "delta": d}));
    let mut st = open(&e, "default", None);
    let mut out = Vec::new();
    out.extend(st.push(format!("event: message_start\ndata: {}\n\n", json!({"type":"message_start","message":{"id":"m1","role":"assistant"}})).as_bytes()));
    out.extend(st.push(ev("content_block_delta", json!({"type":"text_delta","text":"key AKIAZ3XQ"})).as_bytes()));
    out.extend(st.push(ev("content_block_delta", json!({"type":"text_delta","text":"KVN5TLWM7EPD done"})).as_bytes()));
    out.extend(st.push(format!("event: message_stop\ndata: {}\n\n", json!({"type":"message_stop"})).as_bytes()));
    out.extend(st.finish());
    let s = String::from_utf8_lossy(&out).to_string();
    assert!(!s.contains("AKIAZ3XQ") && s.contains("[REDACTED_"), "{s}");
    assert!(s.contains("message_start") && s.contains("message_stop"));
    // signed thinking containing PII cannot be edited: the default policy removes that whole block
    // (start, deltas, signature, stop) and keeps desensitizing the rest of the response
    let ss = |t: &str, i: u32, d: Value| format!("event: {t}\ndata: {}\n\n", json!({"type": t, "index": i, "delta": d}));
    let mut st = open(&e, "default", None);
    let mut raw = String::new();
    raw += &format!("event: content_block_start\ndata: {}\n\n", json!({"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}));
    raw += &ss("content_block_delta", 0, json!({"type":"thinking_delta","thinking":"user phone 13800138000"}));
    raw += &ss("content_block_delta", 0, json!({"type":"signature_delta","signature":"EqQBCgIYAh"}));
    raw += &format!("event: content_block_stop\ndata: {}\n\n", json!({"type":"content_block_stop","index":0}));
    raw += &format!("event: content_block_start\ndata: {}\n\n", json!({"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}));
    raw += &ss("content_block_delta", 1, json!({"type":"text_delta","text":"call 138"}));
    raw += &ss("content_block_delta", 1, json!({"type":"text_delta","text":"00138000 now"}));
    raw += &format!("event: content_block_stop\ndata: {}\n\n", json!({"type":"content_block_stop","index":1}));
    raw += &format!("event: message_stop\ndata: {}\n\n", json!({"type":"message_stop"}));
    let mut out = Vec::new();
    for c in raw.as_bytes().chunks(17) {
        out.extend(st.push(c));
    }
    out.extend(st.finish());
    let s = String::from_utf8_lossy(&out).to_string();
    assert!(!st.is_blocked(), "{s}");
    assert!(!s.contains("thinking_delta") && !s.contains("signature_delta") && !s.contains("EqQBCg"), "{s}");
    assert!(!s.contains("13800138000") && s.contains("138****8000") && s.contains("message_stop"), "{s}");
    assert!(st.stats().warnings.iter().any(|w| w.contains("removed")));
    // the text block (index 1) survives intact, including its start/stop events
    assert!(s.contains("\"index\":1") && s.matches("event: content_block_stop").count() == 1);
}

#[test]
fn incomplete_stream_and_buffer_limit_fail_closed() {
    let e = engine();
    // upstream cut mid-event: the partial event is scanned, not dropped
    let mut st = open(&e, "default", None);
    st.push(b"data: call 13800138000");
    let out = st.finish();
    assert!(st.stats().incomplete_tail);
    assert!(String::from_utf8_lossy(&out).contains("138****8000"));
    // buffer cap exceeded in strict mode => block, never "release what we have"
    let mut st = e.open_stream(&admin(), &StreamOptions { policy_id: Some("default".into()), max_buffer_bytes: Some(64), ..Default::default() }).unwrap();
    let mut out = Vec::new();
    for _ in 0..20 {
        out.extend(st.push(openai_chunk("0123456789").as_bytes()));
    }
    assert!(st.is_blocked());
    assert!(!String::from_utf8_lossy(&out).contains("0123456789"));
}

#[test]
fn window_falls_back_to_strict_when_not_provable() {
    let e = engine();
    // default gitleaks rules include unbounded patterns (e.g. PEM blocks) => no provable window
    assert!(e.ruleset().window_bound_all().is_none());
    assert!(!e.ruleset().window_blockers().is_empty());
    let st = open(&e, "rules-only", Some("window"));
    assert_eq!(st.stats().effective_mode, "strict");
    assert!(st.stats().fallback_reason.as_ref().unwrap().contains("provable"));
    // NLP policies never use windows either
    let st = open(&e, "default", Some("window"));
    assert_eq!(st.stats().effective_mode, "strict");
}

fn bounded_engine() -> Arc<DlpEngine> {
    let e = engine();
    for id in e.ruleset().window_blockers() {
        e.store.set_rule_enabled(&id, false).unwrap();
    }
    e.reload_rules(&admin()).unwrap();
    assert!(e.ruleset().window_bound_all().is_some(), "blockers left: {:?}", e.ruleset().window_blockers());
    e
}

#[test]
fn window_mode_releases_early_but_equals_full_text_result() {
    let e = bounded_engine();
    let bound = e.ruleset().window_bound_all().unwrap();
    let filler = "这是一段普通的说明文字，没有任何敏感信息。".repeat(40);
    let text = format!("{filler}联系人手机13800138000，邮箱 zhangsan@example.com，密钥 AKIAZ3XQKVN5TLWM7EPD。{filler}尾部 {VALID_ID} 结束。");
    // reference: full-text result with the same policy
    let mut r = req(&text, "rules-only", Mode::Sanitize);
    r.detectors = None;
    let reference = e.process(&admin(), &r).unwrap().sanitized_text.unwrap();
    assert!(!reference.contains("13800138000"));
    // stream it with awkward chunk sizes
    for chunk_chars in [1usize, 2, 3, 7, 11, 40] {
        let mut st = open(&e, "rules-only", Some("window"));
        assert_eq!(st.stats().effective_mode, "window");
        let chars: Vec<char> = text.chars().collect();
        let mut out = Vec::new();
        let mut first_release_at = None;
        for (i, c) in chars.chunks(chunk_chars).enumerate() {
            let piece: String = c.iter().collect();
            let o = st.push(openai_chunk(&piece).as_bytes());
            if first_release_at.is_none() && !o.is_empty() {
                first_release_at = Some(i * chunk_chars);
            }
            out.extend(o);
        }
        out.extend(st.push(openai_finish().as_bytes()));
        out.extend(st.finish());
        let got = openai_text(&out);
        assert_eq!(got, reference, "chunk={chunk_chars} bound={bound}");
        assert!(first_release_at.is_some() && first_release_at.unwrap() < chars.len() / 2, "window mode should release early (chunk={chunk_chars})");
        assert!(st.stats().max_held_bytes < text.len(), "held {} of {}", st.stats().max_held_bytes, text.len());
        assert!(!String::from_utf8_lossy(&out).contains("13800138000"));
    }
}

#[test]
fn window_mode_never_leaks_entity_straddling_release_point() {
    let e = bounded_engine();
    let bound = e.ruleset().window_bound_all().unwrap();
    // place the secret at every offset relative to the hold-back boundary
    for pad in (0..(bound + 40)).step_by(3) {
        let text = format!("{}tel 13800138000 end{}", "x".repeat(pad), "y".repeat(bound + 10));
        let mut st = open(&e, "rules-only", Some("window"));
        let mut out = Vec::new();
        for c in text.as_bytes().chunks(5) {
            out.extend(st.push(openai_chunk(std::str::from_utf8(c).unwrap()).as_bytes()));
        }
        out.extend(st.push(openai_finish().as_bytes()));
        out.extend(st.finish());
        let t = openai_text(&out);
        assert!(!t.contains("13800138000") && t.contains("138****8000"), "pad={pad}: {t}");
    }
}

#[test]
fn nlp_mandatory_policy_blocks_stream_when_detector_down() {
    let dead = dlp_detectors::NlpConfig { base_url: "http://127.0.0.1:9".into(), ..Default::default() };
    let e = engine_with(|c| c.nlp = Some(dead.clone()));
    let mut st = open(&e, "strict", None);
    let mut out = st.push(openai_chunk("hello").as_bytes());
    out.extend(st.push(openai_finish().as_bytes()));
    out.extend(st.finish());
    assert!(st.is_blocked(), "fail_closed policy must block, not pass through unscanned");
    assert!(!String::from_utf8_lossy(&out).contains("hello"));
}
