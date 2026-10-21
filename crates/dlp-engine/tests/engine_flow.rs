mod common;
use common::*;
use dlp_core::*;
use dlp_engine::*;

fn types(r: &DetectResponse) -> Vec<&str> {
    r.entities.iter().map(|e| e.entity_type.as_str()).collect()
}

#[test]
fn scenario_a_cn_phone_masked() {
    let e = engine();
    let text = "张三的手机号是13800138000。";
    let r = e.process(&admin(), &req(text, "default", Mode::Sanitize)).unwrap();
    // phone: deterministic rule + checksum-like prefix validation, masked per policy
    let phone = r.entities.iter().find(|x| x.entity_type == "PHONE_NUMBER").unwrap();
    assert_eq!((phone.start, phone.end), (7, 18));
    assert_eq!(&text[phone.byte_start..phone.byte_end], "13800138000");
    assert!(r.sanitized_text.as_deref().unwrap().ends_with("138****8000。"));
    // the name is found by the contextual rule `cn-name-possessive` (NOT hard-coded): disabling that rule
    // removes it, and with the NLP detectors absent nothing else claims it
    assert!(types(&r).contains(&"PERSON"));
    e.store.set_rule_enabled("cn-name-possessive", false).unwrap();
    e.reload_rules(&admin()).unwrap();
    let r = e.process(&admin(), &req(text, "default", Mode::Sanitize)).unwrap();
    assert_eq!(types(&r), ["PHONE_NUMBER"]);
}

#[test]
fn scenario_c_credentials() {
    let e = engine();
    let t = format!("config: aws_access_key_id = {FAKE_AWS}\nnote ok");
    let r = e.process(&admin(), &req(&t, "default", Mode::Sanitize)).unwrap();
    assert_eq!(r.decision, Verdict::Modified);
    let out = r.sanitized_text.unwrap();
    assert!(!out.contains(FAKE_AWS) && out.contains("[REDACTED_"), "{out}");
    // private key => desensitized like everything else: the whole PEM block becomes a fixed label,
    // the surrounding text survives, nothing is refused
    let r = e.process(&admin(), &req(&format!("here is my key\n{FAKE_PEM}\nthanks"), "default", Mode::Sanitize)).unwrap();
    assert_eq!(r.decision, Verdict::Modified);
    let out = r.sanitized_text.unwrap();
    assert_eq!(out, "here is my key\n[REDACTED_PRIVATE_KEY]\nthanks");
    // a truncated paste (no END marker) is still wiped to the end of the text
    let r = e.process(&admin(), &req("key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEe", "default", Mode::Sanitize)).unwrap();
    assert_eq!(r.sanitized_text.unwrap(), "key:\n[REDACTED_PRIVATE_KEY]");
    // blocking is an explicit opt-in (policy `block-secrets` or a per-request override)
    let r = e.process(&admin(), &req(&format!("k\n{FAKE_PEM}"), "block-secrets", Mode::Sanitize)).unwrap();
    assert_eq!(r.decision, Verdict::Blocked);
    assert!(r.sanitized_text.is_none());
    let mut o = req(&format!("k\n{FAKE_PEM}"), "default", Mode::Sanitize);
    o.action_overrides.insert("PRIVATE_KEY".into(), Action::Block);
    assert_eq!(e.process(&admin(), &o).unwrap().decision, Verdict::Blocked);
    // overrides can only be stricter: downgrading a REDACT to PASS is ignored
    let mut o = req(&format!("k {FAKE_AWS}"), "default", Mode::Sanitize);
    o.action_overrides.insert("CLOUD_CREDENTIAL".into(), Action::Pass);
    assert!(!e.process(&admin(), &o).unwrap().sanitized_text.unwrap().contains(FAKE_AWS));
}

#[test]
fn false_positive_controls() {
    let e = engine();
    let cases = [
        "订单号 110101199003070027 已发货",            // 18 digits, bad checksum
        "流水号 1234567890123456 请查收",                // 16 digits, no banking context
        "commit 5d41402abc4b2a76b9719d911017c592 merged", // md5-looking hex
        "今天天气不错，我们去公园散步吧",
        "版本 1.2.3.4 已发布，端口 8080",
        "the password field is required",
    ];
    for t in cases {
        let r = e.process(&admin(), &req(t, "default", Mode::Detect)).unwrap();
        let bad: Vec<_> = r.entities.iter().filter(|x| x.action != Action::Pass && x.action != Action::Audit).collect();
        assert!(bad.is_empty(), "false positive on {t:?}: {:?}", bad.iter().map(|x| (&x.entity_type, &x.rule_id)).collect::<Vec<_>>());
    }
    // valid ID is detected, even with separators
    let r = e.process(&admin(), &req(&format!("身份证 {VALID_ID}"), "default", Mode::Detect)).unwrap();
    assert_eq!(types(&r), ["CN_ID_CARD"]);
    let r = e.process(&admin(), &req("身份证 110101 19900307 002X", "default", Mode::Detect)).unwrap();
    assert_eq!(types(&r), ["CN_ID_CARD"]);
}

#[test]
fn bank_card_needs_context_and_luhn() {
    let e = engine();
    let ok = e.process(&admin(), &req("请转账到银行卡 6222 0212 3456 7890 008", "default", Mode::Detect)).unwrap();
    // Luhn-valid synthetic number
    let digits = "622202123456789000";
    let _ = (ok, digits);
    // compute a Luhn-valid 19-digit number
    let mut body = "622202123456789000".to_string();
    let sum: u32 = body.chars().rev().enumerate().map(|(i, c)| { let d = c.to_digit(10).unwrap(); if i % 2 == 0 { let v = d * 2; if v > 9 { v - 9 } else { v } } else { d } }).sum();
    body.push(char::from_digit((10 - sum % 10) % 10, 10).unwrap());
    let with_ctx = e.process(&admin(), &req(&format!("请转账到银行卡 {body} 谢谢"), "default", Mode::Sanitize)).unwrap();
    assert_eq!(types(&with_ctx), ["BANK_CARD"], "{:?}", with_ctx.entities.iter().map(|x| &x.rule_id).collect::<Vec<_>>());
    assert!(with_ctx.sanitized_text.unwrap().contains("[REDACTED_BANK_CARD]"));
    let no_ctx = e.process(&admin(), &req(&format!("编号 {body} 谢谢"), "default", Mode::Detect)).unwrap();
    assert!(no_ctx.entities.is_empty(), "digits without banking context must not be a bank card");
}

#[test]
fn unicode_offsets_are_consistent() {
    let e = engine();
    let t = "😀你好😀 mail: a.b@example.com 😀手机13800138000";
    let r = e.process(&admin(), &req(t, "default", Mode::Detect)).unwrap();
    assert_eq!(r.entities.len(), 2);
    for en in &r.entities {
        let by_bytes = &t[en.byte_start..en.byte_end];
        let by_chars: String = t.chars().skip(en.start).take(en.end - en.start).collect();
        assert_eq!(by_bytes, by_chars);
    }
}

#[test]
fn overlapping_entities_resolved_and_sanitized_once() {
    let e = engine();
    // the bank-card context rule and the credit-card rule both match a Visa test number
    let t = "银行卡号 4111 1111 1111 1111 请核对";
    let r = e.process(&admin(), &req(t, "default", Mode::Sanitize)).unwrap();
    assert_eq!(r.entities.len(), 1, "{:?}", r.entities.iter().map(|x| &x.rule_id).collect::<Vec<_>>());
    assert_eq!(r.sanitized_text.unwrap().matches("[REDACTED_").count(), 1);
}

#[test]
fn limits_are_enforced() {
    let e = engine_with(|c| {
        c.limits.max_text_bytes = 100;
        c.limits.max_batch = 2;
    });
    assert!(matches!(e.process(&admin(), &req(&"a".repeat(101), "default", Mode::Detect)), Err(DlpError::TooLarge(_))));
    let rs = e.process_many(&admin(), &[req("a", "default", Mode::Detect), req("b", "default", Mode::Detect), req("c", "default", Mode::Detect)]);
    assert!(rs.iter().all(|r| matches!(r, Err(DlpError::TooLarge(_)))));
}

#[test]
fn scopes_are_enforced() {
    let e = engine();
    let ro = Caller::new("t", "u", &["detect"]);
    assert!(e.process(&ro, &req("x", "default", Mode::Detect)).is_ok());
    assert!(matches!(e.process(&ro, &req("x", "default", Mode::Sanitize)), Err(DlpError::Forbidden(_))));
    assert!(matches!(e.reload_rules(&ro), Err(DlpError::Forbidden(_))));
    let mut r = req("x", "default", Mode::Detect);
    r.reveal_values = true;
    assert!(matches!(e.process(&ro, &r), Err(DlpError::Forbidden(_))));
}

#[test]
fn scenario_d_roundtrip_and_attacks() {
    let e = engine();
    let alice = user("tenantA", "alice");
    // PII is anonymized reversibly under the "reversible" policy; the credential never is
    let t = format!("请给张三发送一封邮件，邮箱是zhangsan@example.com。联系人：李四。密钥 {FAKE_AWS}");
    let mut r = req(&t, "reversible", Mode::Anonymize);
    r.session_id = Some("chat-1".into());
    let out = e.process(&alice, &r).unwrap();
    let sent = out.sanitized_text.clone().unwrap();
    assert!(sent.contains("[EMAIL_ADDRESS_1]") && sent.contains("[PERSON_1]"), "{sent}");
    assert!(!sent.contains("zhangsan@example.com") && !sent.contains(FAKE_AWS), "{sent}");
    assert!(sent.contains("[REDACTED_"), "credential must be irreversibly redacted: {sent}");
    // model answers using placeholders
    let reply = "已向[EMAIL_ADDRESS_1]发送邮件，称呼[PERSON_1]。另外[EMAIL_ADDRESS_9]不存在。";
    let back = e.deanonymize(&alice, "chat-1", reply, Direction::Response, Some("reversible"), true).unwrap();
    assert!(back.text.contains("zhangsan@example.com") && back.text.contains("李四"), "{}", back.text);
    assert_eq!(back.unknown_placeholders, 1);
    assert!(back.text.contains("[EMAIL_ADDRESS_9]"));
    // cross-session restore fails
    assert!(e.deanonymize(&alice, "chat-2", reply, Direction::Response, None, true).is_err());
    // another tenant / another user with the same session id
    assert!(e.deanonymize(&user("tenantB", "alice"), "chat-1", reply, Direction::Response, None, true).is_err());
    assert!(e.deanonymize(&user("tenantA", "mallory"), "chat-1", reply, Direction::Response, None, true).is_err());
    // missing scope
    let weak = Caller::new("tenantA", "alice", &["detect", "anonymize"]);
    assert!(matches!(e.deanonymize(&weak, "chat-1", reply, Direction::Response, None, true), Err(DlpError::Forbidden(_))));
    // restoring into a tool call is not an allowed direction by default
    assert!(matches!(e.deanonymize(&alice, "chat-1", reply, Direction::ToolInput, None, true), Err(DlpError::Forbidden(_))));
    // skipping the response check needs its own scope
    assert!(matches!(e.deanonymize(&alice, "chat-1", reply, Direction::Response, None, false), Err(DlpError::Forbidden(_))));
    // expiry
    e.vault.expire_now(&alice, "chat-1");
    assert!(e.deanonymize(&alice, "chat-1", reply, Direction::Response, None, true).is_err());
}

#[test]
fn scenario_e_model_response_is_checked_independently() {
    let e = engine();
    let mut a = req("hello", "default", Mode::Anonymize);
    a.session_id = Some("s".into());
    e.process(&user("t", "u"), &a).unwrap(); // creates the session
    // the model leaks a key and a card number in its answer; restore must happen AFTER the check
    let reply = format!("好的。你的密钥是 {FAKE_AWS}，以及银行卡 4111 1111 1111 1111。");
    let out = e.deanonymize(&user("t", "u"), "s", &reply, Direction::Response, Some("default"), true).unwrap();
    assert!(!out.text.contains(FAKE_AWS) && !out.text.contains("4111 1111"), "{}", out.text);
    // a response carrying a private key is desensitized too (and placeholders are still restored)
    let bad = format!("here you go\n{FAKE_PEM}");
    let out = e.deanonymize(&user("t", "u"), "s", &bad, Direction::Response, Some("default"), true).unwrap();
    assert_eq!(out.text, "here you go\n[REDACTED_PRIVATE_KEY]");
    // only a policy that explicitly says BLOCK refuses (and then nothing is restored)
    assert!(e.deanonymize(&user("t", "u"), "s", &bad, Direction::Response, Some("block-secrets"), true).is_err());
    // response-direction policy differs from request: phone in a model answer is masked, not anonymized
    let mut r = req("联系 13800138000", "reversible", Mode::Anonymize);
    r.direction = Direction::Response;
    let o = e.process(&user("t", "u"), &r).unwrap();
    assert_eq!(o.sanitized_text.unwrap(), "联系 138****8000");
}

#[test]
fn scenario_g_hot_reload_atomic_and_rollback() {
    let e = engine();
    let c = admin();
    let probe = "工单号 TKT-884213 请跟进";
    assert!(e.process(&c, &req(probe, "default", Mode::Detect)).unwrap().entities.is_empty());
    let v0 = e.ruleset().version;
    // add a rule directly in SQLite, as an operator would
    let mut rule = dlp_rules::RuleDef::simple("ticket-id", "TICKET_ID", "custom", "medium", r"\bTKT-\d{6}\b");
    rule.source = "custom".into();
    e.store.upsert_rule(&rule).unwrap();
    // not active until reload
    assert!(e.process(&c, &req(probe, "default", Mode::Detect)).unwrap().entities.is_empty());
    let rep = e.reload_rules(&c).unwrap();
    assert!(rep.changed && rep.ruleset_version > v0);
    let r = e.process(&c, &req(probe, "default", Mode::Detect)).unwrap();
    assert_eq!(types(&r), ["TICKET_ID"]);
    // a broken rule must not replace the working set
    let mut bad = dlp_rules::RuleDef::simple("broken", "BROKEN", "custom", "low", r"(unclosed[");
    bad.source = "custom".into();
    e.store.upsert_rule(&bad).unwrap();
    let err = e.reload_rules(&c).unwrap_err();
    assert!(matches!(err, DlpError::Rules(_)), "{err}");
    assert_eq!(e.ruleset().version, rep.ruleset_version, "old rule set must keep serving");
    assert_eq!(types(&e.process(&c, &req(probe, "default", Mode::Detect)).unwrap()), ["TICKET_ID"]);
    // remove the bad rule, reload ok, then roll back to the version before ticket-id
    e.store.delete_rule("broken").unwrap();
    e.reload_rules(&c).unwrap();
    let rb = e.rollback_rules(&c, v0).unwrap();
    assert!(rb.changed);
    assert!(e.process(&c, &req(probe, "default", Mode::Detect)).unwrap().entities.is_empty());
    // audit trail exists for all edits made through SQL
    let a = e.store.audit_for("ticket-id").unwrap();
    assert!(a.iter().any(|x| x.2 == "rules" && x.3 == "INSERT"), "{a:?}");
    assert!(!e.store.audit_for("broken").unwrap().is_empty());
}

#[test]
fn reload_under_concurrent_load_never_errors() {
    let e = engine();
    let stop = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|s| {
        for _ in 0..4 {
            s.spawn(|| {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let r = e.process(&admin(), &req("tel 13800138000 mail a@b.co", "default", Mode::Sanitize)).unwrap();
                    assert!(r.entities.len() >= 2);
                }
            });
        }
        for i in 0..6 {
            let mut rule = dlp_rules::RuleDef::simple("flip", "FLIP", "custom", "low", r"\bflip-\d+\b");
            rule.source = "custom".into();
            rule.confidence = 0.5 + (i as f32) * 0.01;
            e.store.upsert_rule(&rule).unwrap();
            e.reload_rules(&admin()).unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    });
}

#[test]
fn degraded_nlp_is_reported_not_hidden() {
    // NLP configured but nothing listens there
    let dead = dlp_detectors::NlpConfig { base_url: "http://127.0.0.1:9".into(), ..Default::default() };
    let e = engine_with(|c| c.nlp = Some(dead.clone()));
    let mut r = DetectRequest::new("联系人：王小明，电话13800138000");
    r.mode = Some(Mode::Sanitize);
    // default policy: presidio is NOT mandatory -> works but flags degradation
    r.policy_id = Some("default".into());
    let out = e.process(&admin(), &r).unwrap();
    assert!(out.degraded);
    assert_eq!(out.decision, Verdict::Modified);
    let g = out.detector_status.iter().find(|d| d.name == "presidio").unwrap();
    assert!(g.enabled && !g.ran && g.error.is_some(), "{g:?}");
    assert!(out.warnings.iter().any(|w| w.contains("presidio")));
    // strict policy: presidio is mandatory + fail_closed -> blocked, never "clean"
    r.policy_id = Some("strict".into());
    let out = e.process(&admin(), &r).unwrap();
    assert_eq!(out.decision, Verdict::Blocked);
    assert!(out.blocked_reason.unwrap().contains("presidio"));
    assert!(out.sanitized_text.is_none());
    // audit-only (fail_open_with_audit): proceeds but flagged
    r.policy_id = Some("audit-only".into());
    let out = e.process(&admin(), &r).unwrap();
    assert!(out.degraded && out.decision != Verdict::Blocked);
}

#[test]
fn policy_and_detector_restrictions() {
    let e = engine();
    // caller cannot drop mandatory detectors by narrowing the list
    let mut r = req("key AKIAZ3XQKVN5TLWM7EPD", "default", Mode::Detect);
    r.detectors = Some(vec!["dictionary".into()]);
    let out = e.process(&admin(), &r).unwrap();
    assert!(out.entities.iter().any(|x| x.entity_type == "CLOUD_CREDENTIAL"));
    assert!(matches!(e.process(&admin(), &req("x", "no-such-policy", Mode::Detect)), Err(DlpError::NotFound(_))));
}

#[test]
fn dictionary_terms_and_internal_assets() {
    let e = engine();
    let c = admin();
    let t = "请评估夜莺计划的风险，并检查 Orion-CRM 与 192.168.10.5、db.internal 的连通性，报价：￥1,200,000元";
    let r = e.process(&c, &req(t, "default", Mode::Sanitize)).unwrap();
    let ty = types(&r);
    for want in ["PROJECT_NAME", "INTERNAL_SYSTEM", "IP_INTERNAL", "INTERNAL_DOMAIN", "FINANCIAL_AMOUNT"] {
        assert!(ty.contains(&want), "missing {want} in {ty:?}");
    }
    // public IPs are not high risk by default: PASS
    let r = e.process(&c, &req("DNS 8.8.8.8", "default", Mode::Detect)).unwrap();
    assert!(r.entities.iter().all(|x| x.action == Action::Pass));
    // operators add confidential terms at runtime
    e.store.add_dictionary_terms("dict-confidential", &["蓝鲸机密".to_string()]).unwrap();
    e.reload_rules(&c).unwrap();
    assert!(types(&e.process(&c, &req("关于蓝鲸机密的讨论", "default", Mode::Detect)).unwrap()).contains(&"CONFIDENTIAL_TERM"));
}

#[test]
fn issued_placeholders_are_shielded_but_cannot_hide_secrets() {
    let e = engine();
    let u = user("t", "u");
    let mut r = req("联系人：张三，邮箱 zhangsan@example.com", "reversible", Mode::Anonymize);
    r.session_id = Some("sh".into());
    let sent = e.process(&u, &r).unwrap().sanitized_text.unwrap();
    assert!(sent.contains("[PERSON_1]") && sent.contains("[EMAIL_ADDRESS_1]"), "{sent}");
    // (1) the model repeats placeholders: the response check must leave them intact
    let reply = "好的，已联系[PERSON_1]，邮箱[EMAIL_ADDRESS_1]。";
    let back = e.deanonymize(&u, "sh", reply, Direction::Response, Some("reversible"), true).unwrap();
    assert_eq!(back.text, "好的，已联系张三，邮箱zhangsan@example.com。");
    assert!(back.response_check.unwrap().entities.is_empty(), "issued placeholders must not be detected");
    // (2) multi-turn: history that already contains placeholders is not anonymized again
    let mut r2 = req(&format!("上文：{sent} 再确认一次 [PERSON_1] 和新邮箱 other@example.org"), "reversible", Mode::Anonymize);
    r2.session_id = Some("sh".into());
    let out = e.process(&u, &r2).unwrap();
    let t = out.sanitized_text.unwrap();
    assert!(t.contains("[PERSON_1]") && t.contains("[EMAIL_ADDRESS_2]"), "{t}");
    assert!(!t.contains("[EMAIL_ADDRESS_3]"));
    // (3) a secret wrapped in placeholder-looking brackets is NOT shielded (only exact issued tokens are)
    let mut r3 = req(&format!("see [{FAKE_AWS}] and [PERSON_9]"), "default", Mode::Sanitize);
    r3.session_id = Some("sh".into());
    let o = e.process(&u, &r3).unwrap();
    assert!(!o.sanitized_text.unwrap().contains(FAKE_AWS));
}
