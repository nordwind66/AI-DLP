# Rule database (SQLite)

File: `ai_dlp.db` (path via `--db` / `DLP_DB` / `db_path`). WAL mode, foreign keys on, busy timeout 5 s. Schema in
`database/migrations/001_init.sql`; `schema_migrations` records applied versions; every migration runs in its own
`IMMEDIATE` transaction, and a database newer than the binary is refused (downgrade protection).

| table | purpose |
|---|---|
| `rules` | one row per rule: `id` (original gitleaks id preserved), name, description, category, `entity_type`, `risk_level`, `engine` (`regex`/`secret`/`dictionary`), `keywords`, `entropy`, `secret_group`, `context_keywords/mode/window`, `confidence`, `evidence`, `priority`, `enabled`, `irreversible`, `skip_report`, `locked`, `source`, `source_version`, `compat` (`native`/`translated`/`unsupported`/`path_only`), `compat_note`, timestamps |
| `rule_patterns` | `kind` (`regex` content pattern, `path` gitleaks file-path regex), `pattern`, `ordinal` |
| `rule_validators` | validator `name` + JSON `params` (`luhn`, `card_brand`, `cn_id_card`, `cn_mobile`, `cn_uscc`, `cn_postal`, `cn_name`, `ipv4_private`, `ipv4_public`, `jwt`, `iban`, `digit_count`, `not_trivial`, `entropy_min`, `min_len`, `mixed_alnum`, `not_placeholder`) |
| `rule_allowlists` | per rule (`rule_id`) or global (`rule_id IS NULL`): `condition` OR/AND, `regex_target` (secret/match/line), `regexes`, `paths`, `stopwords`, `commits` |
| `rule_required` | gitleaks composite rules: `required_rule_id`, `within_lines`, `within_columns` |
| `rule_dictionaries` | confidential terms for `engine=dictionary` rules (company/project/department/system/custom), case/whole-word flags |
| `entity_types` | catalogue of types seen (auto-maintained) with category/default risk/reversible |
| `policies`, `policy_rules` | policies (`fail_mode`, JSON config: detectors, mandatory detectors, thresholds, stream mode, unmodifiable handling) and ordered match rules (`rule_id`/`entity_type`/`category`/`risk_level` → action, direction, min_confidence, replacement) |
| `rule_versions` | content-addressed full snapshots (`fingerprint`, JSON) – the rollback source; exactly one `active` |
| `rule_imports` | one row per import: source/version/commit, counts (inserted/updated/unchanged/unsupported/skipped_locked), JSON report, `version_before` |
| `rule_audit` | written by triggers on every INSERT/UPDATE/DELETE of rules, patterns, validators, allowlists, dictionaries, policies |
| `schema_migrations` | applied schema versions |

Context modes: `boost` (+0.1 confidence if a keyword is within the window), `require` (drop unless found – bank cards need
banking context), `deny` (drop if found in the window *before* the match – a phone-shaped number after "流水号").

## Importing gitleaks

```
gitleaks-importer --db ai_dlp.db import rules/gitleaks.toml --source-version v8-main --commit b58d3f1…
```
Preserves ids, regex, keywords (lower-cased like upstream), entropy, secretGroup, allowlists (`[allowlist]`, `[[allowlists]]`
with `targetRules`, `[[rules.allowlists]]`, `condition`, `regexTarget`), `[[rules.required]]`, `skipReport`, `path`-only rules.
Each regex goes through the Go→Rust translator and is compiled; failures are stored `enabled=0, compat='unsupported'` with the
reason (nothing is dropped silently). Re-import is idempotent (`unchanged`); changed rules are updated, `locked=1` rules are
skipped, rules that disappeared upstream are reported and kept. A snapshot is taken **before** the import
(`version_before`), so `gitleaks-importer rollback <version>` undoes it. Result on the pinned config: 222 rules, 0 unsupported,
182 translated (dialect rewrites), 1 `path_only` (`pkcs12-file`, not applicable to text), compile ≈ 0.17 s.

## Editing rules

Any SQL client works; changes take effect at `POST /v1/rules/reload` (or `--watch-rules-secs N`, or `dlp_reload_rules()`). The
audit trail is automatic: `SELECT * FROM rule_audit WHERE key='my-rule'`.
