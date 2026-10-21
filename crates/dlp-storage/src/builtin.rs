//! Importer for our own rule/policy TOML (the built-in PII, financial, credential-context and
//! internal-asset rules shipped in `rules/`). The file shape is `RuleSetDef`-like plus policies.
use crate::*;
use dlp_policy::PolicyDef;
use dlp_rules::*;
use rusqlite::params;
use serde::Deserialize;

#[derive(Debug, Deserialize, Default)]
pub struct BuiltinFile {
    #[serde(default)]
    pub source_version: String,
    #[serde(default)]
    pub rules: Vec<RuleDef>,
    #[serde(default)]
    pub global_allowlists: Vec<AllowlistDef>,
    #[serde(default)]
    pub dictionaries: Vec<DictEntry>,
    #[serde(default)]
    pub policies: Vec<PolicyDef>,
}

#[derive(Debug, Default, serde::Serialize)]
pub struct BuiltinImportReport {
    pub rules_inserted: usize,
    pub rules_updated: usize,
    pub rules_unchanged: usize,
    pub rules_skipped_locked: usize,
    pub dictionary_terms: usize,
    pub policies: usize,
    pub errors: Vec<String>,
}

pub fn import_builtin_toml(store: &Store, text: &str) -> StoreResult<BuiltinImportReport> {
    let file: BuiltinFile = toml::from_str(text).map_err(|e| StoreError::Other(format!("builtin toml: {e}")))?;
    let mut rep = BuiltinImportReport::default();
    // validate by compiling before touching the database
    let def = RuleSetDef { version: 0, rules: file.rules.clone(), global_allowlists: file.global_allowlists.clone(), dictionaries: file.dictionaries.clone() };
    if let Err(errs) = RuleSet::compile(&def, &CompileOptions::default()) {
        return Err(StoreError::Other(format!("builtin rules do not compile: {}", errs.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; "))));
    }
    let existing = store.load_ruleset_def()?;
    let ex: std::collections::HashMap<&str, &RuleDef> = existing.rules.iter().map(|r| (r.id.as_str(), r)).collect();
    store.with_tx(|tx| {
        for r in &file.rules {
            let mut r = r.clone();
            if r.source.is_empty() || r.source == "custom" {
                r.source = "builtin".into();
            }
            if r.source_version.is_empty() {
                r.source_version = file.source_version.clone();
            }
            if r.name.is_empty() {
                r.name = r.id.clone();
            }
            // normalise defaults exactly as the database stores them, so unchanged rules compare equal
            if r.evidence.is_empty() {
                r.evidence = "pattern".into();
            }
            if r.compat.is_empty() {
                r.compat = "native".into();
            }
            match ex.get(r.id.as_str()) {
                None => {
                    write_rule(tx, &r)?;
                    rep.rules_inserted += 1;
                }
                Some(old) if **old == r => rep.rules_unchanged += 1,
                Some(_) => {
                    let locked: i64 = tx.query_row("SELECT locked FROM rules WHERE id=?1", params![r.id], |x| x.get(0))?;
                    if locked != 0 {
                        rep.rules_skipped_locked += 1;
                    } else {
                        write_rule(tx, &r)?;
                        rep.rules_updated += 1;
                    }
                }
            }
        }
        for a in &file.global_allowlists {
            // global allowlists of the builtin set are identified by description
            let exists: i64 = tx.query_row("SELECT COUNT(*) FROM rule_allowlists WHERE rule_id IS NULL AND description=?1", params![a.description], |x| x.get(0))?;
            if exists == 0 {
                insert_allowlist(tx, None, a)?;
            }
        }
        for d in &file.dictionaries {
            rep.dictionary_terms += tx.execute("INSERT OR IGNORE INTO rule_dictionaries(rule_id,term,case_sensitive,whole_word) VALUES(?1,?2,?3,?4)", params![d.rule_id, d.term, d.case_sensitive as i64, d.whole_word as i64])?;
        }
        Ok(())
    })?;
    for p in &file.policies {
        store.upsert_policy(p)?;
        rep.policies += 1;
    }
    Ok(rep)
}
