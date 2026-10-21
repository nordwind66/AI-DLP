-- AI DLP rule database, schema v1.
-- Everything detection-related lives here; code contains no rule literals except tests.

CREATE TABLE entity_types (
    name          TEXT PRIMARY KEY,
    category      TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    default_risk  TEXT NOT NULL DEFAULT 'medium' CHECK (default_risk IN ('low','medium','high','critical')),
    reversible    INTEGER NOT NULL DEFAULT 1       -- may ANONYMIZE be restored from the vault?
);

CREATE TABLE rules (
    id               TEXT PRIMARY KEY,             -- original gitleaks id is preserved verbatim
    name             TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    category         TEXT NOT NULL,                -- pii | contact | financial | credential | internal | business | custom
    entity_type      TEXT NOT NULL,
    risk_level       TEXT NOT NULL CHECK (risk_level IN ('low','medium','high','critical')),
    engine           TEXT NOT NULL CHECK (engine IN ('regex','secret','dictionary')),
    keywords         TEXT NOT NULL DEFAULT '[]',   -- JSON array, prefilter (gitleaks `keywords`)
    entropy          REAL NOT NULL DEFAULT 0,      -- gitleaks `entropy`
    secret_group     INTEGER NOT NULL DEFAULT 0,   -- gitleaks `secretGroup`
    context_keywords TEXT NOT NULL DEFAULT '[]',
    context_mode     TEXT NOT NULL DEFAULT '' CHECK (context_mode IN ('','boost','require','deny')),
    context_window   INTEGER NOT NULL DEFAULT 40,
    confidence       REAL NOT NULL DEFAULT 0.85 CHECK (confidence >= 0 AND confidence <= 1),
    evidence         TEXT NOT NULL DEFAULT 'pattern' CHECK (evidence IN ('pattern','validated')),
    priority         INTEGER NOT NULL DEFAULT 0,
    enabled          INTEGER NOT NULL DEFAULT 1,
    irreversible     INTEGER NOT NULL DEFAULT 0,
    skip_report      INTEGER NOT NULL DEFAULT 0,
    locked           INTEGER NOT NULL DEFAULT 0,   -- 1 = importer must not overwrite local edits
    source           TEXT NOT NULL DEFAULT 'custom',
    source_version   TEXT NOT NULL DEFAULT '',
    compat           TEXT NOT NULL DEFAULT 'native' CHECK (compat IN ('native','translated','unsupported','path_only')),
    compat_note      TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX idx_rules_entity ON rules(entity_type);
CREATE INDEX idx_rules_source ON rules(source);

CREATE TABLE rule_patterns (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id  TEXT NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    kind     TEXT NOT NULL DEFAULT 'regex' CHECK (kind IN ('regex','path')),
    pattern  TEXT NOT NULL,
    ordinal  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_patterns_rule ON rule_patterns(rule_id);

CREATE TABLE rule_validators (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id  TEXT NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    name     TEXT NOT NULL,                        -- luhn | cn_id_card | cn_mobile | jwt | ...
    params   TEXT NOT NULL DEFAULT '{}',
    ordinal  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_validators_rule ON rule_validators(rule_id);

CREATE TABLE rule_allowlists (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id       TEXT REFERENCES rules(id) ON DELETE CASCADE,   -- NULL = global allowlist
    description   TEXT NOT NULL DEFAULT '',
    condition     TEXT NOT NULL DEFAULT 'OR' CHECK (condition IN ('OR','AND')),
    regex_target  TEXT NOT NULL DEFAULT '' CHECK (regex_target IN ('','secret','match','line')),
    regexes       TEXT NOT NULL DEFAULT '[]',
    paths         TEXT NOT NULL DEFAULT '[]',
    stopwords     TEXT NOT NULL DEFAULT '[]',
    commits       TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX idx_allow_rule ON rule_allowlists(rule_id);

CREATE TABLE rule_required (                         -- gitleaks `[[rules.required]]` composite rules
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id          TEXT NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    required_rule_id TEXT NOT NULL,
    within_lines     INTEGER,
    within_columns   INTEGER
);

CREATE TABLE rule_dictionaries (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id        TEXT NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    term           TEXT NOT NULL,
    case_sensitive INTEGER NOT NULL DEFAULT 0,
    whole_word     INTEGER NOT NULL DEFAULT 1,
    UNIQUE(rule_id, term)
);

CREATE TABLE policies (
    id           TEXT PRIMARY KEY,
    name         TEXT NOT NULL DEFAULT '',
    description  TEXT NOT NULL DEFAULT '',
    fail_mode    TEXT NOT NULL CHECK (fail_mode IN ('fail_closed','fail_open_with_audit')),
    config       TEXT NOT NULL DEFAULT '{}',        -- detectors, thresholds, stream mode ... (JSON)
    enabled      INTEGER NOT NULL DEFAULT 1,
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE policy_rules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id      TEXT NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    match_kind     TEXT NOT NULL CHECK (match_kind IN ('rule_id','entity_type','category','risk_level')),
    match_value    TEXT NOT NULL,
    direction      TEXT CHECK (direction IS NULL OR direction IN ('request','response','tool_input','tool_output')),
    action         TEXT NOT NULL CHECK (action IN ('PASS','AUDIT','MASK','REDACT','REPLACE','ANONYMIZE','BLOCK')),
    min_confidence REAL,
    replacement    TEXT,
    priority       INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_policy_rules ON policy_rules(policy_id);

CREATE TABLE rule_versions (
    version      INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint  TEXT NOT NULL,
    reason       TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    active       INTEGER NOT NULL DEFAULT 0,
    snapshot     TEXT NOT NULL                       -- full RuleSetDef JSON: enables exact rollback
);

CREATE TABLE rule_imports (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    source             TEXT NOT NULL,
    source_version     TEXT NOT NULL DEFAULT '',
    source_commit      TEXT NOT NULL DEFAULT '',
    imported_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    total              INTEGER NOT NULL,
    inserted           INTEGER NOT NULL,
    updated            INTEGER NOT NULL,
    unchanged          INTEGER NOT NULL,
    unsupported        INTEGER NOT NULL,
    skipped_locked     INTEGER NOT NULL DEFAULT 0,
    version_before     INTEGER,                      -- rule_versions.version snapshot taken before the import
    report             TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE rule_audit (                            -- written by triggers: covers edits from any client
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    table_name TEXT NOT NULL,
    op         TEXT NOT NULL,
    key        TEXT NOT NULL,
    old_value  TEXT,
    new_value  TEXT
);

CREATE TRIGGER trg_rules_ai AFTER INSERT ON rules BEGIN
  INSERT INTO rule_audit(table_name,op,key,new_value) VALUES('rules','INSERT',NEW.id,
    json_object('enabled',NEW.enabled,'risk',NEW.risk_level,'engine',NEW.engine,'entity_type',NEW.entity_type,'source',NEW.source));
END;
CREATE TRIGGER trg_rules_au AFTER UPDATE ON rules BEGIN
  INSERT INTO rule_audit(table_name,op,key,old_value,new_value) VALUES('rules','UPDATE',NEW.id,
    json_object('enabled',OLD.enabled,'risk',OLD.risk_level,'priority',OLD.priority,'confidence',OLD.confidence,'entropy',OLD.entropy),
    json_object('enabled',NEW.enabled,'risk',NEW.risk_level,'priority',NEW.priority,'confidence',NEW.confidence,'entropy',NEW.entropy));
END;
CREATE TRIGGER trg_rules_ad AFTER DELETE ON rules BEGIN
  INSERT INTO rule_audit(table_name,op,key,old_value) VALUES('rules','DELETE',OLD.id,json_object('entity_type',OLD.entity_type,'source',OLD.source));
END;
CREATE TRIGGER trg_patterns_ai AFTER INSERT ON rule_patterns BEGIN
  INSERT INTO rule_audit(table_name,op,key,new_value) VALUES('rule_patterns','INSERT',NEW.rule_id,json_object('kind',NEW.kind,'len',length(NEW.pattern)));
END;
CREATE TRIGGER trg_patterns_au AFTER UPDATE ON rule_patterns BEGIN
  INSERT INTO rule_audit(table_name,op,key,old_value,new_value) VALUES('rule_patterns','UPDATE',NEW.rule_id,json_object('len',length(OLD.pattern)),json_object('len',length(NEW.pattern)));
END;
CREATE TRIGGER trg_patterns_ad AFTER DELETE ON rule_patterns BEGIN
  INSERT INTO rule_audit(table_name,op,key) VALUES('rule_patterns','DELETE',OLD.rule_id);
END;
CREATE TRIGGER trg_allow_ai AFTER INSERT ON rule_allowlists BEGIN
  INSERT INTO rule_audit(table_name,op,key) VALUES('rule_allowlists','INSERT',COALESCE(NEW.rule_id,'<global>'));
END;
CREATE TRIGGER trg_allow_au AFTER UPDATE ON rule_allowlists BEGIN
  INSERT INTO rule_audit(table_name,op,key) VALUES('rule_allowlists','UPDATE',COALESCE(NEW.rule_id,'<global>'));
END;
CREATE TRIGGER trg_allow_ad AFTER DELETE ON rule_allowlists BEGIN
  INSERT INTO rule_audit(table_name,op,key) VALUES('rule_allowlists','DELETE',COALESCE(OLD.rule_id,'<global>'));
END;
CREATE TRIGGER trg_dict_ai AFTER INSERT ON rule_dictionaries BEGIN
  INSERT INTO rule_audit(table_name,op,key) VALUES('rule_dictionaries','INSERT',NEW.rule_id);
END;
CREATE TRIGGER trg_dict_ad AFTER DELETE ON rule_dictionaries BEGIN
  INSERT INTO rule_audit(table_name,op,key) VALUES('rule_dictionaries','DELETE',OLD.rule_id);
END;
CREATE TRIGGER trg_valid_ai AFTER INSERT ON rule_validators BEGIN
  INSERT INTO rule_audit(table_name,op,key,new_value) VALUES('rule_validators','INSERT',NEW.rule_id,NEW.name);
END;
CREATE TRIGGER trg_valid_ad AFTER DELETE ON rule_validators BEGIN
  INSERT INTO rule_audit(table_name,op,key,old_value) VALUES('rule_validators','DELETE',OLD.rule_id,OLD.name);
END;
CREATE TRIGGER trg_policy_au AFTER UPDATE ON policies BEGIN
  INSERT INTO rule_audit(table_name,op,key) VALUES('policies','UPDATE',NEW.id);
END;
CREATE TRIGGER trg_policyrules_ai AFTER INSERT ON policy_rules BEGIN
  INSERT INTO rule_audit(table_name,op,key,new_value) VALUES('policy_rules','INSERT',NEW.policy_id,NEW.match_kind||':'||NEW.match_value||'->'||NEW.action);
END;
CREATE TRIGGER trg_policyrules_ad AFTER DELETE ON policy_rules BEGIN
  INSERT INTO rule_audit(table_name,op,key) VALUES('policy_rules','DELETE',OLD.policy_id);
END;
