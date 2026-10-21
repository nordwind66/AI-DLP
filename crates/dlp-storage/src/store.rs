use dlp_policy::{FailMode, PolicyDef, PolicyRule};
use dlp_rules::*;
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Other(String),
}
pub type StoreResult<T> = Result<T, StoreError>;

const MIGRATIONS: &[(i64, &str, &str)] = &[(1, "init", include_str!("../../../database/migrations/001_init.sql"))];

pub struct Store {
    conn: Mutex<Connection>,
    pub path: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VersionInfo {
    pub version: i64,
    pub fingerprint: String,
    pub reason: String,
    pub created_at: String,
    pub active: bool,
}

fn jarr(v: &[String]) -> String {
    serde_json::to_string(v).unwrap_or_else(|_| "[]".into())
}
fn parr(s: &str) -> Vec<String> {
    serde_json::from_str(s).unwrap_or_default()
}

impl Store {
    pub fn open(path: &str) -> StoreResult<Store> {
        let conn = Connection::open(path)?;
        Self::init(conn, path)
    }
    pub fn open_in_memory() -> StoreResult<Store> {
        Self::init(Connection::open_in_memory()?, ":memory:")
    }
    fn init(mut conn: Connection, path: &str) -> StoreResult<Store> {
        conn.pragma_update(None, "foreign_keys", true)?;
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));")?;
        let current: i64 = conn.query_row("SELECT COALESCE(MAX(version),0) FROM schema_migrations", [], |r| r.get(0))?;
        let latest = MIGRATIONS.last().map(|m| m.0).unwrap_or(0);
        if current > latest {
            return Err(StoreError::Other(format!("database schema v{current} is newer than this binary (v{latest}); refusing to open (downgrade protection)")));
        }
        for (v, name, sql) in MIGRATIONS.iter().filter(|m| m.0 > current) {
            // each migration is atomic: a failure leaves the database at the previous version
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute_batch(sql)?;
            tx.execute("INSERT INTO schema_migrations(version,name) VALUES(?1,?2)", params![v, name])?;
            tx.commit()?;
        }
        Ok(Store { conn: Mutex::new(conn), path: path.to_string() })
    }

    pub fn schema_version(&self) -> StoreResult<i64> {
        Ok(self.conn.lock().query_row("SELECT COALESCE(MAX(version),0) FROM schema_migrations", [], |r| r.get(0))?)
    }

    /// Monotonic change marker: the newest audit row id. Any edit (from any client) bumps it.
    pub fn change_counter(&self) -> StoreResult<i64> {
        Ok(self.conn.lock().query_row("SELECT COALESCE(MAX(id),0) FROM rule_audit", [], |r| r.get(0))?)
    }

    pub fn with_tx<T>(&self, f: impl FnOnce(&Transaction) -> StoreResult<T>) -> StoreResult<T> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let out = f(&tx)?;
        tx.commit()?;
        Ok(out)
    }

    // ---------------------------------------------------------------- rules
    /// Read the complete rule set inside one read transaction (consistent snapshot).
    pub fn load_ruleset_def(&self) -> StoreResult<RuleSetDef> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let def = read_def(&tx)?;
        Ok(def)
    }

    pub fn upsert_rule(&self, r: &RuleDef) -> StoreResult<()> {
        self.with_tx(|tx| write_rule(tx, r))
    }
    pub fn delete_rule(&self, id: &str) -> StoreResult<bool> {
        self.with_tx(|tx| Ok(tx.execute("DELETE FROM rules WHERE id=?1", params![id])? > 0))
    }
    pub fn set_rule_enabled(&self, id: &str, enabled: bool) -> StoreResult<bool> {
        self.with_tx(|tx| Ok(tx.execute("UPDATE rules SET enabled=?2, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?1", params![id, enabled as i64])? > 0))
    }
    pub fn add_dictionary_terms(&self, rule_id: &str, terms: &[String]) -> StoreResult<usize> {
        self.with_tx(|tx| {
            let mut n = 0;
            for t in terms {
                n += tx.execute("INSERT OR IGNORE INTO rule_dictionaries(rule_id,term) VALUES(?1,?2)", params![rule_id, t])?;
            }
            Ok(n)
        })
    }

    // ------------------------------------------------------------- versions
    /// Snapshot `def` as a new active version (idempotent: identical fingerprint re-activates).
    pub fn publish_version(&self, def: &RuleSetDef, fingerprint: &str, reason: &str) -> StoreResult<i64> {
        self.with_tx(|tx| {
            let existing: Option<i64> = tx.query_row("SELECT version FROM rule_versions WHERE fingerprint=?1 ORDER BY version DESC LIMIT 1", params![fingerprint], |r| r.get(0)).optional()?;
            let v = match existing {
                Some(v) => v,
                None => {
                    let mut d = def.clone();
                    d.version = 0;
                    tx.execute("INSERT INTO rule_versions(fingerprint,reason,snapshot) VALUES(?1,?2,?3)", params![fingerprint, reason, serde_json::to_string(&d)?])?;
                    tx.last_insert_rowid()
                }
            };
            tx.execute("UPDATE rule_versions SET active=(version=?1)", params![v])?;
            Ok(v)
        })
    }
    pub fn list_versions(&self) -> StoreResult<Vec<VersionInfo>> {
        let conn = self.conn.lock();
        let mut st = conn.prepare("SELECT version,fingerprint,reason,created_at,active FROM rule_versions ORDER BY version DESC")?;
        let rows = st.query_map([], |r| Ok(VersionInfo { version: r.get(0)?, fingerprint: r.get(1)?, reason: r.get(2)?, created_at: r.get(3)?, active: r.get::<_, i64>(4)? != 0 }))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
    pub fn active_version(&self) -> StoreResult<Option<i64>> {
        Ok(self.conn.lock().query_row("SELECT version FROM rule_versions WHERE active=1", [], |r| r.get(0)).optional()?)
    }
    pub fn snapshot_of(&self, version: i64) -> StoreResult<Option<RuleSetDef>> {
        let s: Option<String> = self.conn.lock().query_row("SELECT snapshot FROM rule_versions WHERE version=?1", params![version], |r| r.get(0)).optional()?;
        match s {
            Some(s) => {
                let mut d: RuleSetDef = serde_json::from_str(&s)?;
                d.version = version;
                Ok(Some(d))
            }
            None => Ok(None),
        }
    }
    /// Replace the live rule tables with the snapshot of `version` (atomic). The caller then runs
    /// the normal validate+compile+swap path, so a bad snapshot can never take down serving rules.
    pub fn restore_version(&self, version: i64) -> StoreResult<()> {
        let def = self.snapshot_of(version)?.ok_or_else(|| StoreError::Other(format!("version {version} not found")))?;
        self.with_tx(|tx| {
            for t in ["rule_allowlists", "rule_dictionaries", "rule_required", "rule_validators", "rule_patterns", "rules"] {
                tx.execute(&format!("DELETE FROM {t}"), [])?;
            }
            for r in &def.rules {
                write_rule(tx, r)?;
            }
            for a in &def.global_allowlists {
                insert_allowlist(tx, None, a)?;
            }
            for d in &def.dictionaries {
                tx.execute("INSERT OR IGNORE INTO rule_dictionaries(rule_id,term,case_sensitive,whole_word) VALUES(?1,?2,?3,?4)", params![d.rule_id, d.term, d.case_sensitive as i64, d.whole_word as i64])?;
            }
            Ok(())
        })
    }

    // ------------------------------------------------------------- policies
    pub fn load_policies(&self) -> StoreResult<Vec<PolicyDef>> {
        let conn = self.conn.lock();
        let mut out = Vec::new();
        let mut st = conn.prepare("SELECT id,name,description,fail_mode,config FROM policies WHERE enabled=1 ORDER BY id")?;
        let rows: Vec<(String, String, String, String, String)> = st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?.collect::<Result<_, _>>()?;
        for (id, name, desc, fm, cfg) in rows {
            let mut v: Value = serde_json::from_str(&cfg).unwrap_or(Value::Object(Default::default()));
            let o = v.as_object_mut().ok_or_else(|| StoreError::Other("policy config must be an object".into()))?;
            o.insert("id".into(), id.clone().into());
            o.insert("name".into(), name.into());
            o.insert("description".into(), desc.into());
            o.insert("fail_mode".into(), fm.into());
            let mut rs = conn.prepare("SELECT match_kind,match_value,direction,action,min_confidence,replacement,priority FROM policy_rules WHERE policy_id=?1 ORDER BY id")?;
            let rules: Vec<Value> = rs
                .query_map(params![id], |r| {
                    Ok(serde_json::json!({
                        "match_kind": r.get::<_, String>(0)?, "match_value": r.get::<_, String>(1)?,
                        "direction": r.get::<_, Option<String>>(2)?, "action": r.get::<_, String>(3)?,
                        "min_confidence": r.get::<_, Option<f64>>(4)?, "replacement": r.get::<_, Option<String>>(5)?,
                        "priority": r.get::<_, i64>(6)?
                    }))
                })?
                .collect::<Result<_, _>>()?;
            o.insert("rules".into(), Value::Array(rules));
            let p: PolicyDef = serde_json::from_value(v).map_err(|e| StoreError::Other(format!("policy '{id}': {e}")))?;
            out.push(p);
        }
        Ok(out)
    }

    pub fn upsert_policy(&self, p: &PolicyDef) -> StoreResult<()> {
        self.with_tx(|tx| {
            let mut cfg = serde_json::to_value(p)?;
            let o = cfg.as_object_mut().unwrap();
            for k in ["id", "name", "description", "fail_mode", "rules"] {
                o.remove(k);
            }
            let fm = match p.fail_mode {
                FailMode::FailClosed => "fail_closed",
                FailMode::FailOpenWithAudit => "fail_open_with_audit",
            };
            tx.execute(
                "INSERT INTO policies(id,name,description,fail_mode,config) VALUES(?1,?2,?3,?4,?5)
                 ON CONFLICT(id) DO UPDATE SET name=?2,description=?3,fail_mode=?4,config=?5,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                params![p.id, p.name, p.description, fm, serde_json::to_string(&cfg)?],
            )?;
            tx.execute("DELETE FROM policy_rules WHERE policy_id=?1", params![p.id])?;
            for r in &p.rules {
                insert_policy_rule(tx, &p.id, r)?;
            }
            Ok(())
        })
    }

    /// Audit rows for one key (rule id / policy id), newest first.
    pub fn audit_for(&self, key: &str) -> StoreResult<Vec<(i64, String, String, String, String)>> {
        let conn = self.conn.lock();
        let mut st = conn.prepare("SELECT id,ts,table_name,op,key FROM rule_audit WHERE key=?1 ORDER BY id DESC LIMIT 200")?;
        let rows = st.query_map(params![key], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub fn audit_tail(&self, n: usize) -> StoreResult<Vec<(i64, String, String, String, String)>> {
        let conn = self.conn.lock();
        let mut st = conn.prepare("SELECT id,ts,table_name,op,key FROM rule_audit ORDER BY id DESC LIMIT ?1")?;
        let rows = st.query_map(params![n as i64], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }
}

fn insert_policy_rule(tx: &Transaction, pid: &str, r: &PolicyRule) -> StoreResult<()> {
    let kind = serde_json::to_value(r.match_kind)?.as_str().unwrap_or("entity_type").to_string();
    let dir = r.direction.map(|d| d.as_str().to_string());
    tx.execute(
        "INSERT INTO policy_rules(policy_id,match_kind,match_value,direction,action,min_confidence,replacement,priority) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![pid, kind, r.match_value, dir, r.action.as_str(), r.min_confidence, r.replacement, r.priority],
    )?;
    Ok(())
}

pub(crate) fn insert_allowlist(tx: &Transaction, rule_id: Option<&str>, a: &AllowlistDef) -> StoreResult<()> {
    tx.execute(
        "INSERT INTO rule_allowlists(rule_id,description,condition,regex_target,regexes,paths,stopwords,commits) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![rule_id, a.description, if a.condition.eq_ignore_ascii_case("AND") { "AND" } else { "OR" }, a.regex_target, jarr(&a.regexes), jarr(&a.paths), jarr(&a.stopwords), jarr(&a.commits)],
    )?;
    Ok(())
}

/// Insert-or-replace a rule and all of its child rows.
pub(crate) fn write_rule(tx: &Transaction, r: &RuleDef) -> StoreResult<()> {
    tx.execute(
        "INSERT INTO rules(id,name,description,category,entity_type,risk_level,engine,keywords,entropy,secret_group,context_keywords,context_mode,context_window,confidence,evidence,priority,enabled,irreversible,skip_report,source,source_version,compat,compat_note)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23)
         ON CONFLICT(id) DO UPDATE SET name=?2,description=?3,category=?4,entity_type=?5,risk_level=?6,engine=?7,keywords=?8,entropy=?9,secret_group=?10,context_keywords=?11,context_mode=?12,context_window=?13,confidence=?14,evidence=?15,priority=?16,enabled=?17,irreversible=?18,skip_report=?19,source=?20,source_version=?21,compat=?22,compat_note=?23,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",
        params![r.id, r.name, r.description, r.category, r.entity_type, r.risk_level, r.engine, jarr(&r.keywords), r.entropy, r.secret_group, jarr(&r.context_keywords), r.context_mode, r.context_window as i64, r.confidence as f64, if r.evidence.is_empty() { "pattern" } else { &r.evidence }, r.priority, r.enabled as i64, r.irreversible as i64, r.skip_report as i64, r.source, r.source_version, if r.compat.is_empty() { "native" } else { &r.compat }, r.compat_note],
    )?;
    for t in ["rule_patterns", "rule_validators", "rule_allowlists", "rule_required"] {
        tx.execute(&format!("DELETE FROM {t} WHERE rule_id=?1"), params![r.id])?;
    }
    for (i, p) in r.patterns.iter().enumerate() {
        tx.execute("INSERT INTO rule_patterns(rule_id,kind,pattern,ordinal) VALUES(?1,?2,?3,?4)", params![r.id, p.kind, p.pattern, i as i64])?;
    }
    for (i, v) in r.validators.iter().enumerate() {
        tx.execute("INSERT INTO rule_validators(rule_id,name,params,ordinal) VALUES(?1,?2,?3,?4)", params![r.id, v.name, if v.params.is_null() { "{}".to_string() } else { v.params.to_string() }, i as i64])?;
    }
    for a in &r.allowlists {
        insert_allowlist(tx, Some(&r.id), a)?;
    }
    for q in &r.required {
        tx.execute("INSERT INTO rule_required(rule_id,required_rule_id,within_lines,within_columns) VALUES(?1,?2,?3,?4)", params![r.id, q.rule_id, q.within_lines, q.within_columns])?;
    }
    // keep entity_types catalogue in sync
    tx.execute("INSERT OR IGNORE INTO entity_types(name,category,default_risk,reversible) VALUES(?1,?2,?3,?4)", params![r.entity_type, r.category, r.risk_level, (!r.irreversible) as i64])?;
    Ok(())
}

fn read_def(tx: &Transaction) -> StoreResult<RuleSetDef> {
    let mut def = RuleSetDef::default();
    def.version = tx.query_row("SELECT COALESCE((SELECT version FROM rule_versions WHERE active=1),0)", [], |r| r.get(0))?;
    let mut st = tx.prepare(
        "SELECT id,name,description,category,entity_type,risk_level,engine,keywords,entropy,secret_group,context_keywords,context_mode,context_window,confidence,evidence,priority,enabled,irreversible,skip_report,source,source_version,compat,compat_note FROM rules ORDER BY priority DESC, id",
    )?;
    let rules = st.query_map([], |r| {
        Ok(RuleDef {
            id: r.get(0)?,
            name: r.get(1)?,
            description: r.get(2)?,
            category: r.get(3)?,
            entity_type: r.get(4)?,
            risk_level: r.get(5)?,
            engine: r.get(6)?,
            patterns: vec![],
            keywords: parr(&r.get::<_, String>(7)?),
            entropy: r.get(8)?,
            secret_group: r.get(9)?,
            validators: vec![],
            context_keywords: parr(&r.get::<_, String>(10)?),
            context_mode: r.get(11)?,
            context_window: r.get::<_, i64>(12)? as usize,
            confidence: r.get::<_, f64>(13)? as f32,
            evidence: r.get(14)?,
            priority: r.get(15)?,
            enabled: r.get::<_, i64>(16)? != 0,
            irreversible: r.get::<_, i64>(17)? != 0,
            skip_report: r.get::<_, i64>(18)? != 0,
            source: r.get(19)?,
            source_version: r.get(20)?,
            allowlists: vec![],
            required: vec![],
            compat: r.get(21)?,
            compat_note: r.get(22)?,
        })
    })?;
    let mut rules: Vec<RuleDef> = rules.collect::<Result<_, _>>()?;
    let idx: std::collections::HashMap<String, usize> = rules.iter().enumerate().map(|(i, r)| (r.id.clone(), i)).collect();
    {
        let mut st = tx.prepare("SELECT rule_id,kind,pattern FROM rule_patterns ORDER BY rule_id, ordinal, id")?;
        for row in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))? {
            let (rid, kind, pattern) = row?;
            if let Some(&i) = idx.get(&rid) {
                rules[i].patterns.push(PatternDef { pattern, kind });
            }
        }
        let mut st = tx.prepare("SELECT rule_id,name,params FROM rule_validators ORDER BY rule_id, ordinal, id")?;
        for row in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?)))? {
            let (rid, name, p) = row?;
            if let Some(&i) = idx.get(&rid) {
                rules[i].validators.push(ValidatorDef { name, params: serde_json::from_str(&p).unwrap_or(Value::Null) });
            }
        }
        let mut st = tx.prepare("SELECT rule_id,description,condition,regex_target,regexes,paths,stopwords,commits FROM rule_allowlists ORDER BY id")?;
        for row in st.query_map([], |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?, r.get::<_, String>(4)?, r.get::<_, String>(5)?, r.get::<_, String>(6)?, r.get::<_, String>(7)?)))? {
            let (rid, description, condition, regex_target, rx, paths, sw, commits) = row?;
            let a = AllowlistDef { description, condition, regex_target, regexes: parr(&rx), paths: parr(&paths), stopwords: parr(&sw), commits: parr(&commits) };
            match rid {
                None => def.global_allowlists.push(a),
                Some(rid) => {
                    if let Some(&i) = idx.get(&rid) {
                        rules[i].allowlists.push(a);
                    }
                }
            }
        }
        let mut st = tx.prepare("SELECT rule_id,required_rule_id,within_lines,within_columns FROM rule_required ORDER BY id")?;
        for row in st.query_map([], |r| Ok((r.get::<_, String>(0)?, RequiredDef { rule_id: r.get(1)?, within_lines: r.get(2)?, within_columns: r.get(3)? })))? {
            let (rid, q) = row?;
            if let Some(&i) = idx.get(&rid) {
                rules[i].required.push(q);
            }
        }
        let mut st = tx.prepare("SELECT rule_id,term,case_sensitive,whole_word FROM rule_dictionaries ORDER BY id")?;
        for row in st.query_map([], |r| Ok(DictEntry { rule_id: r.get(0)?, term: r.get(1)?, case_sensitive: r.get::<_, i64>(2)? != 0, whole_word: r.get::<_, i64>(3)? != 0 }))? {
            def.dictionaries.push(row?);
        }
    }
    def.rules = rules;
    Ok(def)
}

pub fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
