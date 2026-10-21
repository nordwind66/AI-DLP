//! Gitleaks TOML -> SQLite importer.
//!
//! Preserves rule ids and every semantic field (regex, keywords, entropy, secretGroup, allowlists
//! incl. condition/regexTarget/stopwords, required rules, path-only rules, skipReport). Each regex
//! is run through the Go->Rust dialect translator and compiled; rules that cannot be represented
//! faithfully are stored with `compat='unsupported'`, `enabled=0` and the exact reason, never
//! dropped silently. Re-importing is idempotent and versioned; an import can be rolled back via the
//! pre-import snapshot recorded in `rule_imports.version_before`.
use crate::*;
use dlp_rules::*;
use rusqlite::params;
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Default)]
pub struct ImportMeta {
    pub source_version: String,
    pub source_commit: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ImportReport {
    pub total: usize,
    pub inserted: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub unsupported: usize,
    pub path_only: usize,
    pub skipped_locked: usize,
    pub translated: usize,
    pub global_allowlists: usize,
    pub incompatible: Vec<(String, String)>,
    pub compile_failures: Vec<(String, String)>,
    pub version_before: Option<i64>,
    pub version_after: Option<i64>,
}

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}
fn sv(v: &Value, k: &str) -> Vec<String> {
    v.get(k).and_then(|x| x.as_array()).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

fn parse_allowlist(a: &Value) -> AllowlistDef {
    AllowlistDef {
        description: s(a, "description"),
        condition: { let c = s(a, "condition"); if c.is_empty() { "OR".into() } else { c.to_uppercase() } },
        regex_target: s(a, "regexTarget"),
        regexes: sv(a, "regexes"),
        paths: sv(a, "paths"),
        stopwords: sv(a, "stopwords"),
        commits: sv(a, "commits"),
    }
}

/// Map a gitleaks rule id to our entity vocabulary / risk. Heuristic by id; overridable by editing
/// the rows afterwards (`locked=1` protects edits from later re-imports).
pub fn classify(id: &str) -> (&'static str, &'static str, i32, f32, &'static str) {
    // (entity_type, risk, priority, confidence, evidence)
    let has = |p: &[&str]| p.iter().any(|x| id.contains(x));
    if has(&["private-key", "privatekey", "pkcs12", "ssh-key", "pgp"]) {
        ("PRIVATE_KEY", "critical", 90, 0.97, "validated")
    } else if id == "generic-api-key" {
        ("API_KEY", "medium", 10, 0.55, "pattern")
    } else if has(&["jwt"]) {
        ("JWT_TOKEN", "high", 60, 0.9, "validated")
    } else if has(&["password", "passwd", "pwd"]) {
        ("PASSWORD", "high", 60, 0.8, "pattern")
    } else if has(&["openai", "anthropic", "huggingface", "cohere", "mistral", "groq", "perplexity", "replicate", "deepseek", "xai-", "gemini", "openrouter"]) {
        ("LLM_API_KEY", "high", 70, 0.95, "validated")
    } else if has(&["aws", "gcp", "azure", "alibaba", "tencent", "digitalocean", "cloudflare", "heroku", "linode", "scaleway", "ibm", "oracle", "yandex", "doppler", "vault", "terraform", "fly-io", "flyio", "databricks", "snowflake"]) {
        ("CLOUD_CREDENTIAL", "high", 70, 0.95, "validated")
    } else if has(&["oauth", "client-secret", "client-id"]) {
        ("OAUTH_CREDENTIAL", "high", 65, 0.9, "validated")
    } else if has(&["refresh"]) {
        ("REFRESH_TOKEN", "high", 65, 0.9, "validated")
    } else if has(&["bearer"]) {
        ("BEARER_TOKEN", "high", 65, 0.85, "pattern")
    } else if has(&["database", "postgres", "mysql", "mongo", "redis", "planetscale", "connection"]) {
        ("DB_CREDENTIAL", "high", 70, 0.9, "validated")
    } else if has(&["token", "access"]) {
        ("ACCESS_TOKEN", "high", 65, 0.92, "validated")
    } else if has(&["secret"]) {
        ("SECRET_KEY", "high", 65, 0.9, "validated")
    } else {
        ("API_KEY", "high", 65, 0.92, "validated")
    }
}

pub fn parse_rules(text: &str, meta: &ImportMeta) -> Result<(Vec<RuleDef>, Vec<AllowlistDef>, ImportReport), String> {
    let doc: toml::Value = toml::from_str(text).map_err(|e| format!("toml parse: {e}"))?;
    let json: Value = serde_json::to_value(doc).map_err(|e| e.to_string())?;
    let mut rep = ImportReport::default();
    let mut rules = Vec::new();
    let mut global: Vec<AllowlistDef> = Vec::new();
    if let Some(a) = json.get("allowlist") {
        global.push(parse_allowlist(a));
    }
    let mut targeted: std::collections::HashMap<String, Vec<AllowlistDef>> = Default::default();
    if let Some(arr) = json.get("allowlists").and_then(|x| x.as_array()) {
        for a in arr {
            let def = parse_allowlist(a);
            let targets = sv(a, "targetRules");
            if targets.is_empty() {
                global.push(def);
            } else {
                for t in targets {
                    targeted.entry(t).or_default().push(def.clone());
                }
            }
        }
    }
    for r in json.get("rules").and_then(|x| x.as_array()).cloned().unwrap_or_default() {
        rep.total += 1;
        let id = s(&r, "id");
        let (entity, risk, prio, conf, evid) = classify(&id);
        let mut def = RuleDef::simple(&id, entity, "credential", risk, "");
        def.patterns.clear();
        def.engine = "secret".into();
        def.name = id.clone();
        def.description = s(&r, "description");
        def.keywords = sv(&r, "keywords").into_iter().map(|k| k.to_lowercase()).collect();
        def.entropy = r.get("entropy").and_then(|x| x.as_f64()).unwrap_or(0.0);
        def.secret_group = r.get("secretGroup").and_then(|x| x.as_i64()).unwrap_or(0);
        def.skip_report = r.get("skipReport").and_then(|x| x.as_bool()).unwrap_or(false);
        def.priority = prio;
        def.confidence = conf;
        def.evidence = evid.into();
        def.irreversible = true; // credentials can never be restored from the vault
        def.source = "gitleaks".into();
        def.source_version = meta.source_version.clone();
        let rx = s(&r, "regex");
        let path = s(&r, "path");
        if !rx.is_empty() {
            def.patterns.push(PatternDef { pattern: rx.clone(), kind: "regex".into() });
        }
        if !path.is_empty() {
            def.patterns.push(PatternDef { pattern: path, kind: "path".into() });
        }
        if let Some(a) = r.get("allowlists").and_then(|x| x.as_array()) {
            def.allowlists.extend(a.iter().map(parse_allowlist));
        }
        if let Some(a) = r.get("allowlist") {
            def.allowlists.push(parse_allowlist(a));
        }
        if let Some(t) = targeted.get(&id) {
            def.allowlists.extend(t.iter().cloned());
        }
        if let Some(req) = r.get("required").and_then(|x| x.as_array()) {
            for q in req {
                def.required.push(RequiredDef { rule_id: s(q, "id"), within_lines: q.get("withinLines").and_then(|x| x.as_i64()), within_columns: q.get("withinColumns").and_then(|x| x.as_i64()) });
            }
        }
        // ---- compatibility check: translate + compile every regex, validate group & allowlists
        let mut notes: Vec<String> = Vec::new();
        let mut problem: Option<String> = None;
        if rx.is_empty() {
            if def.patterns.iter().any(|p| p.kind == "path") {
                def.compat = "path_only".into();
                def.compat_note = "file-path-only rule: not applicable to prompt/response text".into();
                rep.path_only += 1;
            } else {
                problem = Some("rule has neither regex nor path".into());
            }
        } else {
            match compat::compile(&rx) {
                Ok((re, tr)) => {
                    notes.extend(tr.notes);
                    if def.secret_group > 0 && def.secret_group as usize >= re.captures_len() {
                        problem = Some(format!("secretGroup {} exceeds regex groups {}", def.secret_group, re.captures_len() - 1));
                    }
                }
                Err(e) => problem = Some(format!("regex not representable: {e}")),
            }
        }
        for a in &def.allowlists {
            for g in &a.regexes {
                if let Err(e) = compat::compile(g) {
                    problem = Some(format!("allowlist regex not representable: {e}"));
                }
            }
        }
        if let Some(p) = problem {
            def.enabled = false;
            def.compat = "unsupported".into();
            def.compat_note = p.clone();
            rep.unsupported += 1;
            rep.incompatible.push((id.clone(), p));
        } else if !notes.is_empty() {
            def.compat = "translated".into();
            def.compat_note = notes.join("; ");
            rep.translated += 1;
        } else if def.compat.is_empty() {
            def.compat = "native".into();
        }
        rules.push(def);
    }
    for g in &global {
        for rx in &g.regexes {
            if let Err(e) = compat::compile(rx) {
                rep.compile_failures.push(("<global allowlist>".into(), e));
            }
        }
    }
    rep.global_allowlists = global.len();
    Ok((rules, global, rep))
}

pub fn import_gitleaks_toml(store: &Store, text: &str, meta: &ImportMeta) -> StoreResult<ImportReport> {
    let (rules, global, mut rep) = parse_rules(text, meta).map_err(StoreError::Other)?;
    if !rep.compile_failures.is_empty() {
        return Err(StoreError::Other(format!("global allowlist regex failed to compile: {:?}", rep.compile_failures)));
    }
    // snapshot BEFORE any change so the import can be rolled back
    let before = store.load_ruleset_def()?;
    let fp_before = {
        let mut c = before.clone();
        c.version = 0;
        sha256_hex(&serde_json::to_vec(&c)?)
    };
    rep.version_before = Some(store.publish_version(&before, &fp_before, &format!("pre-import gitleaks {}", meta.source_version))?);
    let existing: std::collections::HashMap<String, RuleDef> = before.rules.iter().filter(|r| r.source == "gitleaks").map(|r| (r.id.clone(), r.clone())).collect();
    let incoming_ids: std::collections::HashSet<&str> = rules.iter().map(|r| r.id.as_str()).collect();
    store.with_tx(|tx| {
        for r in &rules {
            match existing.get(&r.id) {
                None => {
                    // refuse to hijack a non-gitleaks rule with the same id
                    let other: i64 = tx.query_row("SELECT COUNT(*) FROM rules WHERE id=?1", params![r.id], |x| x.get(0))?;
                    if other > 0 {
                        rep.incompatible.push((r.id.clone(), "id collides with a non-gitleaks rule; skipped".into()));
                        continue;
                    }
                    write_rule(tx, r)?;
                    rep.inserted += 1;
                }
                Some(old) => {
                    let mut cmp_old = old.clone();
                    cmp_old.source_version = r.source_version.clone();
                    // admin-owned toggles: keep local `enabled` choice when upstream is unchanged
                    let locked: i64 = tx.query_row("SELECT locked FROM rules WHERE id=?1", params![r.id], |x| x.get(0))?;
                    if locked != 0 {
                        rep.skipped_locked += 1;
                    } else if cmp_old == *r {
                        rep.unchanged += 1;
                    } else {
                        write_rule(tx, r)?;
                        rep.updated += 1;
                    }
                }
            }
        }
        // global allowlists belong to the gitleaks source: replace them wholesale
        tx.execute("DELETE FROM rule_allowlists WHERE rule_id IS NULL AND description LIKE 'gitleaks:%'", [])?;
        for g in &global {
            let mut g = g.clone();
            g.description = format!("gitleaks:{}", g.description);
            insert_allowlist(tx, None, &g)?;
        }
        Ok(())
    })?;
    // rules that existed in an older import but vanished upstream are reported, not deleted
    for id in existing.keys() {
        if !incoming_ids.contains(id.as_str()) {
            rep.incompatible.push((id.clone(), "present in database but removed upstream (kept; disable or delete manually)".into()));
        }
    }
    let after = store.load_ruleset_def()?;
    let fp_after = {
        let mut c = after.clone();
        c.version = 0;
        sha256_hex(&serde_json::to_vec(&c)?)
    };
    rep.version_after = Some(store.publish_version(&after, &fp_after, &format!("import gitleaks {} ({})", meta.source_version, meta.source_commit))?);
    store.with_tx(|tx| {
        tx.execute(
            "INSERT INTO rule_imports(source,source_version,source_commit,total,inserted,updated,unchanged,unsupported,skipped_locked,version_before,report) VALUES('gitleaks',?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![meta.source_version, meta.source_commit, rep.total as i64, rep.inserted as i64, rep.updated as i64, rep.unchanged as i64, rep.unsupported as i64, rep.skipped_locked as i64, rep.version_before, serde_json::to_string(&rep)?],
        )?;
        Ok(())
    })?;
    Ok(rep)
}
