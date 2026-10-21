//! The single place where text is modified. Every detector only *reports*; this executor applies
//! the final, merged, non-overlapping decisions in one left-to-right pass so offsets can never drift.
use crate::mask::{mask_value, redact_label};
use crate::vault::Vault;
use dlp_core::{Action, Caller, DlpError, DlpResult, Entity};

pub struct ExecItem<'a> {
    pub entity: &'a Entity,
    pub action: Action,
    pub replacement: Option<&'a str>,
}

pub struct VaultCtx<'a> {
    pub vault: &'a Vault,
    pub caller: &'a Caller,
    pub session_id: &'a str,
    pub nonce_mode: Option<bool>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Replacement {
    /// index into the entity list the caller passed in
    pub entity_index: usize,
    pub requested: Action,
    /// what actually happened (ANONYMIZE degrades to REDACT without a vault or for irreversible types)
    pub applied: Action,
    /// byte span in the OUTPUT text
    pub out_start: usize,
    pub out_end: usize,
    pub degraded_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExecOutcome {
    pub text: String,
    pub replacements: Vec<Replacement>,
}

/// `items` must be sorted by start offset and non-overlapping (the merger guarantees this).
pub fn execute(text: &str, items: &[ExecItem], vctx: Option<&VaultCtx>) -> DlpResult<ExecOutcome> {
    let mut out = String::with_capacity(text.len() + 32);
    let mut reps = Vec::new();
    let mut cursor = 0usize;
    // Resolve vault placeholders under one lock acquisition per call.
    let mut anonymize_idx: Vec<usize> = Vec::new();
    for (i, it) in items.iter().enumerate() {
        if it.action == Action::Anonymize && !it.entity.irreversible && vctx.is_some() {
            anonymize_idx.push(i);
        }
    }
    let mut placeholders: std::collections::HashMap<usize, String> = std::collections::HashMap::new();
    if let (false, Some(v)) = (anonymize_idx.is_empty(), vctx) {
        v.vault.with_session(v.caller, v.session_id, true, v.nonce_mode, |h| {
            for &i in &anonymize_idx {
                let e = items[i].entity;
                let ph = h.placeholder_for(&e.entity_type, &text[e.start..e.end])?;
                placeholders.insert(i, ph);
            }
            Ok(())
        })?;
    }
    for (i, it) in items.iter().enumerate() {
        let e = it.entity;
        if e.start < cursor || e.end > text.len() || e.start >= e.end || !text.is_char_boundary(e.start) || !text.is_char_boundary(e.end) {
            return Err(DlpError::Internal("executor received overlapping or out-of-range entities".into()));
        }
        let value = &text[e.start..e.end];
        let mut applied = it.action;
        let mut degraded = None;
        let rep: Option<String> = match it.action {
            Action::Pass | Action::Audit => None,
            Action::Block => None,
            Action::Mask => Some(mask_value(&e.entity_type, value)),
            Action::Redact => Some(it.replacement.map(String::from).unwrap_or_else(|| redact_label(&e.entity_type))),
            Action::Replace => Some(it.replacement.map(String::from).unwrap_or_else(|| redact_label(&e.entity_type))),
            Action::Anonymize => match placeholders.get(&i) {
                Some(p) => Some(p.clone()),
                None => {
                    applied = Action::Redact;
                    degraded = Some(if e.irreversible { "irreversible type: never stored in the vault".to_string() } else { "no vault session available".to_string() });
                    Some(redact_label(&e.entity_type))
                }
            },
        };
        out.push_str(&text[cursor..e.start]);
        match rep {
            Some(r) => {
                let s = out.len();
                out.push_str(&r);
                reps.push(Replacement { entity_index: i, requested: it.action, applied, out_start: s, out_end: out.len(), degraded_reason: degraded });
            }
            None => out.push_str(value),
        }
        cursor = e.end;
    }
    out.push_str(&text[cursor..]);
    Ok(ExecOutcome { text: out, replacements: reps })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::VaultConfig;
    fn ent(t: &str, s: usize, e: usize) -> Entity {
        Entity::new(t, s, e, "regex", "r")
    }
    #[test]
    fn mixed_actions_single_pass() {
        let text = "请帮张三分析客户资料，他的手机号是13800138000，key=abc。";
        let name = text.find("张三").unwrap();
        let ph = text.find("13800138000").unwrap();
        let (e1, e2) = (ent("PERSON", name, name + 6), ent("PHONE_NUMBER", ph, ph + 11));
        let vault = Vault::new(VaultConfig::default());
        let c = Caller::new("t", "u", &["deanonymize"]);
        let vctx = VaultCtx { vault: &vault, caller: &c, session_id: "s1", nonce_mode: None };
        let items = [ExecItem { entity: &e1, action: Action::Anonymize, replacement: None }, ExecItem { entity: &e2, action: Action::Mask, replacement: None }];
        let o = execute(text, &items, Some(&vctx)).unwrap();
        assert_eq!(o.text, "请帮[PERSON_1]分析客户资料，他的手机号是138****8000，key=abc。");
        let back = vault.deanonymize(&c, "s1", "已为[PERSON_1]整理好客户资料。").unwrap();
        assert_eq!(back.text, "已为张三整理好客户资料。");
    }
    #[test]
    fn anonymize_degrades_for_irreversible_and_without_vault() {
        let text = "k=AKIAXXXX";
        let mut e = ent("API_KEY", 2, 10);
        e.irreversible = true;
        let vault = Vault::new(VaultConfig::default());
        let c = Caller::new("t", "u", &["deanonymize"]);
        let vctx = VaultCtx { vault: &vault, caller: &c, session_id: "s", nonce_mode: None };
        let o = execute(text, &[ExecItem { entity: &e, action: Action::Anonymize, replacement: None }], Some(&vctx)).unwrap();
        assert_eq!(o.text, "k=[REDACTED_API_KEY]");
        assert_eq!(o.replacements[0].applied, Action::Redact);
        assert_eq!(vault.session_count(), 0, "irreversible values must not even create vault state");
        let e2 = ent("PERSON", 0, 1);
        let o = execute("a", &[ExecItem { entity: &e2, action: Action::Anonymize, replacement: None }], None).unwrap();
        assert_eq!(o.text, "[REDACTED_PERSON]");
    }
}
