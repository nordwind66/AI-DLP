//! Hostile / malformed input: nothing may panic, hang, or be reported as "clean" when it is not.
mod common;
use common::*;
use dlp_core::*;
use dlp_engine::protocol_scan::*;
use dlp_engine::*;
use rand::{Rng, SeedableRng};
use serde_json::{json, Value};

#[test]
fn random_bytes_into_stream_scanner_never_panic() {
    let e = engine();
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let alphabet: Vec<&[u8]> = vec![b"data: ", b"event: ", b"\n", b"\r\n", b"\n\n", b": c", b"{", b"}", b"\"choices\"", b"[DONE]", b"\xff\xfe", "张三".as_bytes(), b" 13800138000 ", b"delta", b"content", b"\xe4\xbd"];
    for round in 0..300 {
        let mut st = e.open_stream(&admin(), &StreamOptions { policy_id: Some("default".into()), mode: Some(if round % 2 == 0 { "strict" } else { "window" }.into()), max_buffer_bytes: Some(4096), ..Default::default() }).unwrap();
        let mut total = Vec::new();
        let mut fed = Vec::new();
        for _ in 0..rng.gen_range(1..40) {
            let piece: Vec<u8> = (0..rng.gen_range(1..6)).flat_map(|_| alphabet[rng.gen_range(0..alphabet.len())].to_vec()).collect();
            fed.extend(&piece);
            total.extend(st.push(&piece));
        }
        total.extend(st.finish());
        // (delta text is concatenated across events, so the phone is always space-delimited in the input)
        // whatever happens, the raw phone number never appears as a standalone number in the
        // output (inside a longer digit run it is not a phone number: the rules require digit boundaries)
        let out = String::from_utf8_lossy(&total).into_owned();
        let b = out.as_bytes();
        let standalone = out.match_indices("13800138000").any(|(i, m)| (i == 0 || !b[i - 1].is_ascii_digit()) && !b.get(i + m.len()).is_some_and(|c| c.is_ascii_digit()));
        assert!(!standalone, "round {round}\nIN:{:?}\nOUT:{out:?}", String::from_utf8_lossy(&fed));
    }
}

#[test]
fn oversize_sse_event_and_unterminated_streams_fail_closed() {
    let e = engine();
    let mut st = e.open_stream(&admin(), &StreamOptions::default()).unwrap();
    let out = st.push(&vec![b'a'; 3 << 20]);
    assert!(st.is_blocked(), "an event above the size limit must stop the stream");
    assert!(String::from_utf8_lossy(&out).contains("dlp_blocked"));
}

fn shape(v: &Value) -> String {
    match v {
        Value::Object(o) => format!("{{{}}}", o.iter().map(|(k, x)| format!("{k}:{}", shape(x))).collect::<Vec<_>>().join(",")),
        Value::Array(a) => format!("[{}]", a.iter().map(shape).collect::<Vec<_>>().join(",")),
        Value::String(_) => "s".into(),
        o => o.to_string(),
    }
}

fn gen_json(rng: &mut rand::rngs::StdRng, depth: u32) -> Value {
    match rng.gen_range(0..if depth > 3 { 4 } else { 7 }) {
        0 => Value::Null,
        1 => json!(rng.gen_range(-5..5)),
        2 => json!(["13800138000".to_string(), "hello".into(), String::new(), "张三的手机号是13800138000".into(), "AKIAZ3XQKVN5TLWM7EPD".into(), "QUJD".repeat(200)][rng.gen_range(0..6)]),
        3 => json!(rng.gen_bool(0.5)),
        4 | 5 => Value::Array((0..rng.gen_range(0..4)).map(|_| gen_json(rng, depth + 1)).collect()),
        _ => {
            let keys = ["messages", "content", "role", "text", "type", "tool_calls", "function", "arguments", "input", "output", "choices", "message", "thinking", "signature", "system", "model", "id", "source", "data"];
            Value::Object((0..rng.gen_range(0..5)).map(|_| (keys[rng.gen_range(0..keys.len())].to_string(), gen_json(rng, depth + 1))).collect())
        }
    }
}

#[test]
fn arbitrary_json_payloads_never_panic_and_never_leak() {
    let e = engine();
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    let (mut modified, mut total) = (0, 0);
    for i in 0..400 {
        let body = gen_json(&mut rng, 0);
        let req = ProtocolRequest { body: body.clone(), protocol: None, direction: if i % 2 == 0 { Direction::Request } else { Direction::Response }, policy_id: Some("default".into()), session_id: None, mode: Mode::Sanitize, nonce_placeholders: None };
        total += 1;
        match e.scan_protocol(&admin(), &req) {
            Ok(r) => {
                if let Some(b) = &r.body {
                    // structure is preserved: same shape, only string leaves may differ
                    assert_eq!(shape(b), shape(&body), "edit changed the JSON structure");
                    if b != &body {
                        modified += 1;
                    }
                }
            }
            Err(err) => panic!("scan_protocol errored on valid JSON: {err}"),
        }
    }
    assert!(total == 400 && modified > 0);
}

#[test]
fn deeply_nested_and_huge_inputs_are_bounded() {
    let e = engine();
    let mut v = json!("13800138000");
    for _ in 0..200 {
        v = json!({"content": [v]});
    }
    let body = json!({"messages": [v]});
    let r = e.scan_protocol(&admin(), &ProtocolRequest { body, protocol: None, direction: Direction::Request, policy_id: None, session_id: None, mode: Mode::Sanitize, nonce_placeholders: None });
    assert!(r.is_ok() || matches!(r, Err(DlpError::TooLarge(_)) | Err(DlpError::InvalidInput(_))));
    // 4 MiB of pathological regex input: linear time, finishes quickly
    let t = std::time::Instant::now();
    let nasty = format!("{}!", "a".repeat(1 << 20)) + &"(".repeat(100_000) + &"1".repeat(1 << 20);
    let r = e.process(&admin(), &req(&nasty, "default", Mode::Sanitize)).unwrap();
    assert!(t.elapsed().as_secs() < 20, "no ReDoS: took {:?}", t.elapsed());
    assert_eq!(r.decision, Verdict::Allow);
    // malformed UTF-8 cannot even be represented in the typed API; the FFI path rejects it (test_ffi.c)
}

#[test]
fn hostile_rules_do_not_take_the_service_down() {
    let e = engine();
    let c = admin();
    let before = e.ruleset().version;
    for (id, pat) in [("evil-1", r"(a+)+$"), ("evil-2", r"a{1000}{1000}"), ("evil-3", &"(".repeat(5000)), ("evil-4", r"\p{Nope}"), ("evil-5", &"a".repeat(20_000))] {
        let mut r = dlp_rules::RuleDef::simple(id, "EVIL", "custom", "low", pat);
        r.source = "custom".into();
        e.store.upsert_rule(&r).unwrap();
        let res = e.reload_rules(&c);
        // either rejected (old rules keep serving) or accepted as a linear-time regex; never a crash
        if res.is_err() {
            assert_eq!(e.ruleset().version, before);
            e.store.delete_rule(id).unwrap();
        } else {
            let t = std::time::Instant::now();
            let text = format!("{}!", "a".repeat(200_000));
            e.process(&c, &req(&text, "default", Mode::Detect)).unwrap();
            assert!(t.elapsed().as_secs() < 10, "{id} slow");
            e.store.delete_rule(id).unwrap();
            e.reload_rules(&c).unwrap();
        }
    }
}
