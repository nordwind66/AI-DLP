mod common;
use common::*;
use dlp_core::*;
use dlp_engine::protocol_scan::*;
use dlp_engine::*;
use serde_json::{json, Value};

fn scan(e: &DlpEngine, body: Value, dir: Direction, policy: &str, mode: Mode) -> ProtocolResult {
    e.scan_protocol(&admin(), &ProtocolRequest { body, protocol: None, direction: dir, policy_id: Some(policy.into()), session_id: None, mode, nonce_placeholders: None }).unwrap()
}

/// All JSON pointers whose value differs between a and b.
fn diff(a: &Value, b: &Value, base: &str, out: &mut Vec<String>) {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            assert_eq!(x.keys().collect::<Vec<_>>(), y.keys().collect::<Vec<_>>(), "key set/order changed at {base}");
            for (k, v) in x {
                diff(v, &y[k], &format!("{base}/{k}"), out);
            }
        }
        (Value::Array(x), Value::Array(y)) => {
            assert_eq!(x.len(), y.len(), "array length changed at {base}");
            for (i, (p, q)) in x.iter().zip(y).enumerate() {
                diff(p, q, &format!("{base}/{i}"), out);
            }
        }
        _ => {
            if a != b {
                out.push(base.to_string());
            }
        }
    }
}

#[test]
fn openai_chat_request_only_text_fields_change() {
    let e = engine();
    let body = json!({
        "model": "gpt-x", "temperature": 0.2, "stream": false,
        "messages": [
            {"role": "system", "content": "You are a helper."},
            {"role": "user", "content": [{"type": "text", "text": "我的手机号是13800138000"}, {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}}]},
            {"role": "assistant", "content": null, "tool_calls": [{"id": "call_abc123", "type": "function", "function": {"name": "send_mail", "arguments": "{\"to\":\"zhangsan@example.com\",\"subject\":\"hi\",\"n\":3}"}}]},
            {"role": "tool", "tool_call_id": "call_abc123", "content": "sent; backup key AKIAZ3XQKVN5TLWM7EPD"},
            {"role": "user", "content": "谢谢"}
        ]
    });
    let r = scan(&e, body.clone(), Direction::Request, "default", Mode::Sanitize);
    assert_eq!(r.protocol, "openai.chat.completions");
    assert_eq!(r.decision, Verdict::Modified);
    let out = r.body.unwrap();
    let mut changed = vec![];
    diff(&body, &out, "", &mut changed);
    changed.sort();
    assert_eq!(changed, ["/messages/1/content/0/text", "/messages/2/tool_calls/0/function/arguments", "/messages/3/content"]);
    assert_eq!(out["messages"][1]["content"][0]["text"], "我的手机号是138****8000");
    assert_eq!(out["messages"][2]["tool_calls"][0]["id"], "call_abc123");
    assert_eq!(out["messages"][3]["tool_call_id"], "call_abc123");
    // tool arguments stay valid JSON with unrelated fields intact
    let args: Value = serde_json::from_str(out["messages"][2]["tool_calls"][0]["function"]["arguments"].as_str().unwrap()).unwrap();
    assert_eq!(args["to"], "z***@example.com");
    assert_eq!(args["n"], 3);
    assert!(!out["messages"][3]["content"].as_str().unwrap().contains("AKIA"));
    // image part reported as skipped, not touched
    assert!(r.slots_skipped.iter().any(|s| s.pointer == "/messages/1/content/1"));
}

#[test]
fn anthropic_thinking_signature_is_never_edited() {
    let e = engine();
    let body = json!({
        "model": "claude-x", "max_tokens": 100,
        "system": [{"type": "text", "text": "be brief", "cache_control": {"type": "ephemeral"}}],
        "messages": [
            {"role": "user", "content": "号码13800138000"},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "user phone is 13900139000", "signature": "EqQBCgIYAhIkMTIz"},
                {"type": "tool_use", "id": "toolu_01", "name": "lookup", "input": {"q": "邮箱 a.b@example.com", "limit": 5}}
            ]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_01", "content": "ok"}]}
        ]
    });
    // default policy (unmodifiable_action = drop): the signed thinking block cannot be edited without
    // invalidating its signature, so the WHOLE block is removed; everything else is desensitized and forwarded
    let r = scan(&e, body.clone(), Direction::Request, "default", Mode::Sanitize);
    assert_eq!(r.decision, Verdict::Modified);
    assert_eq!(r.unmodifiable_findings.len(), 1);
    let out = r.body.unwrap();
    let blocks = out["messages"][1]["content"].as_array().unwrap();
    assert_eq!(blocks.len(), 1, "thinking block (with its signature) removed");
    assert_eq!(blocks[0]["type"], "tool_use");
    assert_eq!(blocks[0]["id"], "toolu_01");
    assert_eq!(blocks[0]["input"]["q"], "邮箱 a***@example.com".replace("a***", "a***"));
    assert_eq!(blocks[0]["input"]["limit"], 5);
    assert_eq!(out["messages"][0]["content"], "号码138****8000");
    assert_eq!(out["system"][0]["cache_control"], json!({"type": "ephemeral"}));
    assert!(!out.to_string().contains("13900139000") && !out.to_string().contains("EqQBCgIY"));
    assert!(r.warnings.iter().any(|w| w.contains("block removed")));
    // opt-in: a policy may prefer to refuse
    let r = scan(&e, body.clone(), Direction::Request, "block-secrets", Mode::Sanitize);
    assert_eq!(r.decision, Verdict::Blocked);
    assert!(r.body.is_none() && r.blocked_reason.unwrap().contains("integrity-protected"));
    // clean thinking is untouched byte for byte
    let mut clean = body.clone();
    clean["messages"][1]["content"][0]["thinking"] = json!("plan the lookup");
    let r = scan(&e, clean.clone(), Direction::Request, "default", Mode::Sanitize);
    let out = r.body.unwrap();
    assert_eq!(out["messages"][1]["content"][0], clean["messages"][1]["content"][0]);
}

#[test]
fn openai_responses_and_response_bodies() {
    let e = engine();
    let req_body = json!({
        "model": "m", "instructions": "x",
        "input": [
            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "key AKIAZ3XQKVN5TLWM7EPD"}]},
            {"type": "function_call", "call_id": "call_1", "name": "f", "arguments": "{\"p\":\"tel 13800138000\"}"},
            {"type": "function_call_output", "call_id": "call_1", "output": "邮箱 a@example.com"},
            {"type": "reasoning", "id": "rs_1", "encrypted_content": "gAAAA", "summary": [{"type": "summary_text", "text": "clean"}]}
        ]
    });
    let r = scan(&e, req_body.clone(), Direction::Request, "default", Mode::Sanitize);
    assert_eq!(r.protocol, "openai.responses");
    let out = r.body.unwrap();
    assert_eq!(out["input"][3], req_body["input"][3]);
    assert_eq!(out["input"][1]["call_id"], "call_1");
    assert!(out["input"][0]["content"][0]["text"].as_str().unwrap().contains("[REDACTED_"));
    // chat completion response: model-generated phone is masked by response policy
    let resp = json!({"id": "chatcmpl-1", "object": "chat.completion", "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "号码是 13800138000"}}], "usage": {"total_tokens": 9}});
    let r = scan(&e, resp.clone(), Direction::Response, "reversible", Mode::Sanitize);
    let out = r.body.unwrap();
    assert_eq!(out["choices"][0]["message"]["content"], "号码是 138****8000");
    assert_eq!(out["usage"], resp["usage"]);
    assert_eq!(r.findings[0].direction, Direction::Response);
    // anthropic response
    let resp = json!({"id": "msg_1", "type": "message", "role": "assistant", "stop_reason": "end_turn", "content": [{"type": "text", "text": "mail me at a.b@example.com"}]});
    let r = scan(&e, resp, Direction::Response, "default", Mode::Sanitize);
    assert_eq!(r.protocol, "anthropic.messages");
    assert_eq!(r.body.unwrap()["content"][0]["text"], "mail me at a***@example.com");
}

#[test]
fn base64_and_dedupe_and_blocking() {
    let e = engine();
    let blob = "QUJD".repeat(300); // 1200 chars of base64
    let same = "手机13800138000";
    let body = json!({"messages": [
        {"role": "user", "content": same}, {"role": "assistant", "content": "ok"}, {"role": "user", "content": same},
        {"role": "user", "content": blob.clone()}
    ]});
    let r = scan(&e, body, Direction::Request, "default", Mode::Sanitize);
    assert_eq!(r.unique_texts_processed, 2, "identical texts must be processed once");
    assert!(r.slots_skipped.iter().any(|s| s.reason == "binary_or_base64"));
    let out = r.body.unwrap();
    assert_eq!(out["messages"][3]["content"], blob.as_str());
    assert_eq!(out["messages"][0]["content"], out["messages"][2]["content"]);
    // a private key in a tool result is redacted in place; the payload still goes through
    let body = json!({"messages": [{"role": "user", "content": "ok"}, {"role": "tool", "tool_call_id": "t", "content": FAKE_PEM}]});
    let r = scan(&e, body.clone(), Direction::Request, "default", Mode::Sanitize);
    assert_eq!(r.decision, Verdict::Modified);
    let out = r.body.unwrap();
    assert_eq!(out["messages"][1]["content"], "[REDACTED_PRIVATE_KEY]");
    assert_eq!(out["messages"][1]["tool_call_id"], "t");
    // BLOCK is opt-in: with `block-secrets` it blocks the whole payload and returns no body
    let r = scan(&e, body, Direction::Request, "block-secrets", Mode::Sanitize);
    assert_eq!(r.decision, Verdict::Blocked);
    assert!(r.body.is_none());
}

#[test]
fn anonymize_consistent_across_slots_and_invalid_tool_args() {
    let e = engine();
    let body = json!({"messages": [
        {"role": "user", "content": "联系人：张三，邮箱 zhangsan@example.com"},
        {"role": "assistant", "content": "好的", "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "f", "arguments": "{\"mail\":\"zhangsan@example.com\"}"}}]}
    ]});
    let r = e.scan_protocol(&admin(), &ProtocolRequest { body, protocol: None, direction: Direction::Request, policy_id: Some("reversible".into()), session_id: Some("sess-p".into()), mode: Mode::Anonymize, nonce_placeholders: None }).unwrap();
    let out = r.body.unwrap();
    let t = out["messages"][0]["content"].as_str().unwrap();
    assert!(t.contains("[PERSON_1]") && t.contains("[EMAIL_ADDRESS_1]"), "{t}");
    let args = out["messages"][1]["tool_calls"][0]["function"]["arguments"].as_str().unwrap();
    assert!(args.contains("[EMAIL_ADDRESS_1]"), "same value must map to the same placeholder across fields: {args}");
    // truncated (invalid) tool arguments are never edited as raw text
    let body = json!({"messages": [{"role": "assistant", "content": "x", "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "f", "arguments": "{\"mail\":\"zhangsan@exa"}}]}]});
    let r = scan(&e, body.clone(), Direction::Request, "rules-only", Mode::Sanitize);
    assert_eq!(r.body.unwrap(), body);
}
