//! Compilation of a [`RuleSetDef`] into an immutable, thread-safe [`RuleSet`], and the scan
//! algorithm. The semantics of `engine = "secret"` rules follow gitleaks `detect.DetectContext` /
//! `detectRule` (commit b58d3f1) step by step; see docs/GITLEAKS_PARITY.md for the mapping.
use crate::compat;
use crate::hyperscan::Hyperscan;
use crate::model::*;
use crate::validators::{self, shannon_entropy, CompiledValidator};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use dlp_core::{Entity, Evidence, RiskLevel};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::cell::OnceCell;
use std::collections::{HashMap, HashSet};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct RuleError {
    pub rule_id: String,
    pub message: String,
}
impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.rule_id, self.message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleGroup {
    /// `engine = "regex"`: PII / contact / financial / internal pattern rules
    Pii,
    /// `engine = "secret"`: gitleaks-semantics credential rules
    Secret,
}

#[derive(Debug, Clone, Default)]
pub struct CompileOptions {
    pub use_hyperscan: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CompileReport {
    pub n_rules: usize,
    pub n_enabled: usize,
    pub path_only_skipped: Vec<String>,
    pub translated_notes: Vec<(String, String)>,
    pub hs_requested: bool,
    pub hs_active: bool,
    pub hs_version: String,
    pub hs_error: Option<String>,
    pub hs_failed: Vec<(String, String)>,
    pub compile_ms: u128,
}

struct CompiledAllowlist {
    and: bool,
    target: Target,
    regex: Option<Regex>,
    stopwords: Vec<String>,
    has_paths: bool,
    has_commits: bool,
}
#[derive(Clone, Copy, PartialEq)]
enum Target {
    Secret,
    Match,
    Line,
}

struct CompiledRequired {
    rule_idx: usize,
    within_lines: Option<i64>,
    within_columns: Option<i64>,
}

struct ContextSpec {
    ac: AhoCorasick,
    require: bool,
    /// reject when a keyword appears in the window BEFORE the match ("流水号", "order id", ...)
    deny: bool,
    window: usize,
}

pub struct CompiledRule {
    pub id: String,
    pub entity_type: String,
    pub category: String,
    pub risk: RiskLevel,
    pub group: Option<RuleGroup>,
    pub priority: i32,
    pub confidence: f32,
    pub evidence: Evidence,
    pub irreversible: bool,
    regexes: Vec<Regex>,
    keywords: Vec<String>,
    entropy: f64,
    secret_group: usize,
    validators: Vec<CompiledValidator>,
    digit_boundary: bool,
    allowlists: Vec<CompiledAllowlist>,
    required: Vec<CompiledRequired>,
    ctx: Option<ContextSpec>,
    skip_report: bool,
    /// hyperscan pattern ids owned by this rule; `None` entry = failed to compile in HS (always candidate)
    hs_ids: Vec<Option<usize>>,
    /// Max bytes a match can span (+context), `None` if unbounded or window-unsafe.
    pub window_bound: Option<usize>,
}

struct DictEntryC {
    rule_idx: usize,
    whole_word: bool,
    case_sensitive: bool,
    term: String,
}

pub struct RuleSet {
    pub version: i64,
    pub fingerprint: String,
    rules: Vec<CompiledRule>,
    by_id: HashMap<String, usize>,
    kw_ac: Option<AhoCorasick>,
    kw_rules: Vec<Vec<usize>>, // keyword pattern id -> rule indices
    no_kw_rules: Vec<usize>,
    global_allow: Vec<CompiledAllowlist>,
    dict_ac: Option<AhoCorasick>,
    dict_entries: Vec<DictEntryC>,
    dict_max_len: usize,
    hs: Option<Hyperscan>,
    pub report: CompileReport,
}

#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub use_hs: bool,
    /// Skip the keyword prefilter (streaming window mode needs a superset of full-text findings).
    pub ignore_keywords: bool,
    /// Restrict to these entity types (empty = all).
    pub entity_filter: Vec<String>,
    pub deadline: Option<Instant>,
    /// gitleaks honours an inline `gitleaks:allow` comment. In a DLP setting that would be a trivial
    /// bypass (the attacker controls the text), so this is OFF unless explicitly enabled.
    pub honor_inline_allow: bool,
}

struct Finding {
    /// start of the whole regex match (gitleaks computes the line from the match, not the secret)
    m_start: usize,
    /// span reported to the caller (the secret group if any, else the whole match)
    start: usize,
    end: usize,
    entropy: f64,
    line: usize,
    col: usize,
}

struct ScanCtx<'a> {
    text: &'a str,
    nl: OnceCell<Vec<usize>>,
}
impl<'a> ScanCtx<'a> {
    fn newlines(&self) -> &Vec<usize> {
        self.nl.get_or_init(|| self.text.bytes().enumerate().filter(|(_, b)| *b == b'\n').map(|(i, _)| i).collect())
    }
    fn line_col(&self, pos: usize) -> (usize, usize) {
        let nl = self.newlines();
        let line = nl.partition_point(|&p| p < pos);
        let line_start = if line == 0 { 0 } else { nl[line - 1] + 1 };
        (line, pos - line_start + 1)
    }
    fn line_text(&self, pos: usize) -> &'a str {
        let nl = self.newlines();
        let line = nl.partition_point(|&p| p < pos);
        let s = if line == 0 { 0 } else { nl[line - 1] + 1 };
        let e = nl.get(line).copied().unwrap_or(self.text.len());
        &self.text[s..e]
    }
}

fn compile_allowlist(a: &AllowlistDef, rule_id: &str) -> Result<CompiledAllowlist, RuleError> {
    let err = |m: String| RuleError { rule_id: rule_id.to_string(), message: m };
    // gitleaks Allowlist.Validate: at least one check must exist
    if a.regexes.is_empty() && a.stopwords.is_empty() && a.paths.is_empty() && a.commits.is_empty() {
        return Err(err("allowlist must contain regexes, stopwords, paths or commits".into()));
    }
    let mut regex = None;
    if !a.regexes.is_empty() {
        let mut parts = Vec::new();
        for r in &a.regexes {
            let t = compat::go_to_rust(r).map_err(|e| err(format!("allowlist regex: {e}")))?;
            parts.push(format!("(?:{})", t.pattern));
        }
        // gitleaks joins with `|` into one expression (joinRegexOr)
        let joined = parts.join("|");
        regex = Some(
            regex::RegexBuilder::new(&joined).size_limit(64 << 20).build().map_err(|e| err(format!("allowlist regex: {e}")))?,
        );
    }
    let target = match a.regex_target.as_str() {
        "" | "secret" => Target::Secret,
        "match" => Target::Match,
        "line" => Target::Line,
        other => return Err(err(format!("bad regexTarget '{other}'"))),
    };
    Ok(CompiledAllowlist {
        and: a.condition.eq_ignore_ascii_case("AND"),
        target,
        regex,
        stopwords: a.stopwords.iter().map(|s| s.to_lowercase()).collect(),
        has_paths: !a.paths.is_empty(),
        has_commits: !a.commits.is_empty(),
    })
}

impl CompiledAllowlist {
    /// gitleaks `checkFindingAllowed`, text-mode: there is no path / commit, so those criteria are
    /// never satisfied (`PathAllowed("")` and `CommitAllowed("")` are false in upstream too).
    fn allows(&self, secret: &str, whole: &str, line: &dyn Fn() -> String) -> bool {
        let target: String;
        let t: &str = match self.target {
            Target::Secret => secret,
            Target::Match => whole,
            Target::Line => {
                target = line();
                &target
            }
        };
        let regex_ok = self.regex.as_ref().map(|r| !t.is_empty() && r.is_match(t)).unwrap_or(false);
        let stop_ok = !self.stopwords.is_empty() && !secret.is_empty() && {
            let l = secret.to_lowercase();
            self.stopwords.iter().any(|w| l.contains(w.as_str()))
        };
        if self.and {
            let mut checks = Vec::new();
            if self.has_commits {
                checks.push(false);
            }
            if self.has_paths {
                checks.push(false);
            }
            if self.regex.is_some() {
                checks.push(regex_ok);
            }
            if !self.stopwords.is_empty() {
                checks.push(stop_ok);
            }
            !checks.is_empty() && checks.iter().all(|&c| c)
        } else {
            regex_ok || stop_ok
        }
    }
    fn line_dependent(&self) -> bool {
        self.target == Target::Line
    }
}

fn pattern_has_dotall(p: &str) -> bool {
    // inline (?s) flag anywhere at the start of a group; good enough for prefilter flags
    p.contains("(?s") || p.contains("(?is") || p.contains("(?si")
}

impl RuleSet {
    pub fn compile(def: &RuleSetDef, opts: &CompileOptions) -> Result<RuleSet, Vec<RuleError>> {
        let t0 = Instant::now();
        let mut errors: Vec<RuleError> = Vec::new();
        let mut report = CompileReport { n_rules: def.rules.len(), hs_requested: opts.use_hyperscan, ..Default::default() };
        let mut rules: Vec<CompiledRule> = Vec::new();
        let mut by_id: HashMap<String, usize> = HashMap::new();
        let mut hs_patterns: Vec<(String, bool)> = Vec::new();
        let mut hs_owner: Vec<usize> = Vec::new();
        let mut seen_ids: HashSet<&str> = HashSet::new();

        // pass 1: compile every enabled rule
        for r in def.rules.iter().filter(|r| r.enabled) {
            if !seen_ids.insert(r.id.as_str()) {
                errors.push(RuleError { rule_id: r.id.clone(), message: "duplicate rule id".into() });
                continue;
            }
            if r.id.trim().is_empty() {
                errors.push(RuleError { rule_id: r.id.clone(), message: "empty rule id".into() });
                continue;
            }
            let group = match r.engine.as_str() {
                "regex" => Some(RuleGroup::Pii),
                "secret" => Some(RuleGroup::Secret),
                "dictionary" => None,
                other => {
                    errors.push(RuleError { rule_id: r.id.clone(), message: format!("unknown engine '{other}'") });
                    continue;
                }
            };
            let Some(risk) = RiskLevel::parse(&r.risk_level) else {
                errors.push(RuleError { rule_id: r.id.clone(), message: format!("bad risk_level '{}'", r.risk_level) });
                continue;
            };
            let content: Vec<&PatternDef> = r.patterns.iter().filter(|p| p.kind == "regex").collect();
            if group.is_some() && content.is_empty() {
                if r.patterns.iter().any(|p| p.kind == "path") {
                    report.path_only_skipped.push(r.id.clone());
                    continue; // file-path-only rule: not applicable to prompt text
                }
                errors.push(RuleError { rule_id: r.id.clone(), message: "rule has no regex pattern".into() });
                continue;
            }
            let mut regexes = Vec::new();
            let mut bad = false;
            let mut max_len: Option<usize> = Some(0);
            for p in &content {
                if p.pattern.len() > 16 * 1024 {
                    errors.push(RuleError { rule_id: r.id.clone(), message: "pattern longer than 16KiB".into() });
                    bad = true;
                    break;
                }
                match compat::compile(&p.pattern) {
                    Ok((re, tr)) => {
                        if !tr.notes.is_empty() {
                            report.translated_notes.push((r.id.clone(), tr.notes.join("; ")));
                        }
                        // upper bound of match length (for streaming-window proofs)
                        let hir = regex_syntax::ParserBuilder::new().build().parse(&tr.pattern);
                        match hir.ok().and_then(|h| h.properties().maximum_len()) {
                            Some(m) => max_len = max_len.map(|x| x.max(m)),
                            None => max_len = None,
                        }
                        regexes.push(re);
                    }
                    Err(e) => {
                        errors.push(RuleError { rule_id: r.id.clone(), message: format!("regex compile failed: {e}") });
                        bad = true;
                        break;
                    }
                }
            }
            if bad {
                continue;
            }
            // gitleaks Rule.Validate: secretGroup must exist in the regex
            if r.secret_group > 0 {
                for re in &regexes {
                    if (r.secret_group as usize) >= re.captures_len() {
                        errors.push(RuleError {
                            rule_id: r.id.clone(),
                            message: format!("invalid secret group {} (max {})", r.secret_group, re.captures_len() - 1),
                        });
                        bad = true;
                    }
                }
                if bad {
                    continue;
                }
            }
            let mut validators_c = Vec::new();
            for v in &r.validators {
                match validators::parse(v) {
                    Ok(c) => validators_c.push(c),
                    Err(e) => {
                        errors.push(RuleError { rule_id: r.id.clone(), message: e });
                        bad = true;
                    }
                }
            }
            let mut allow_c = Vec::new();
            for a in &r.allowlists {
                match compile_allowlist(a, &r.id) {
                    Ok(c) => allow_c.push(c),
                    Err(e) => {
                        errors.push(e);
                        bad = true;
                    }
                }
            }
            if bad {
                continue;
            }
            let ctx = if r.context_keywords.is_empty() {
                None
            } else {
                let pats: Vec<String> = r.context_keywords.iter().map(|k| k.to_lowercase()).collect();
                Some(ContextSpec {
                    ac: AhoCorasickBuilder::new().ascii_case_insensitive(true).build(&pats).map_err(|e| vec![RuleError { rule_id: r.id.clone(), message: format!("context keywords: {e}") }])?,
                    require: r.context_mode == "require",
                    deny: r.context_mode == "deny",
                    window: r.context_window.min(2000),
                })
            };
            let idx = rules.len();
            let evidence = if r.evidence == "validated" || !r.validators.is_empty() { Evidence::Validated } else { Evidence::Pattern };
            let line_dep = allow_c.iter().any(|a| a.line_dependent());
            let window_bound = match (max_len, r.required.is_empty() && !line_dep) {
                (Some(m), true) => Some(m + ctx.as_ref().map(|c| c.window * 2).unwrap_or(0)),
                _ => None,
            };
            let mut hs_ids = Vec::new();
            // Hyperscan only covers rules WITHOUT keywords: keyword-gated rules already get gitleaks'
            // own Aho-Corasick prefilter, and a few of them take seconds to compile in Hyperscan
            // (kubernetes-secret-yaml: 8.6 s) which would make hot reload unusable.
            if opts.use_hyperscan && r.keywords.is_empty() {
                for p in &content {
                    hs_patterns.push((p.pattern.clone(), pattern_has_dotall(&p.pattern)));
                    hs_owner.push(idx);
                    hs_ids.push(Some(hs_patterns.len() - 1));
                }
            }
            by_id.insert(r.id.clone(), idx);
            rules.push(CompiledRule {
                id: r.id.clone(),
                entity_type: r.entity_type.clone(),
                category: r.category.clone(),
                risk,
                group,
                priority: r.priority,
                confidence: r.confidence,
                evidence,
                irreversible: r.irreversible,
                regexes,
                keywords: r.keywords.iter().map(|k| k.to_lowercase()).collect(),
                entropy: r.entropy,
                secret_group: r.secret_group.max(0) as usize,
                digit_boundary: validators_c.iter().any(|c| matches!(c.v, validators::Validator::DigitBoundary)),
                validators: validators_c,
                allowlists: allow_c,
                required: vec![],
                ctx,
                skip_report: r.skip_report,
                hs_ids,
                window_bound,
            });
        }
        // pass 2: required rules (resolve ids)
        for r in def.rules.iter().filter(|r| r.enabled && !r.required.is_empty()) {
            let Some(&idx) = by_id.get(&r.id) else { continue };
            for q in &r.required {
                match by_id.get(&q.rule_id) {
                    Some(&ri) => rules[idx].required.push(CompiledRequired { rule_idx: ri, within_lines: q.within_lines, within_columns: q.within_columns }),
                    None => errors.push(RuleError { rule_id: r.id.clone(), message: format!("required rule '{}' not found or disabled", q.rule_id) }),
                }
            }
        }
        let mut global_allow = Vec::new();
        for a in &def.global_allowlists {
            match compile_allowlist(a, "<global>") {
                Ok(c) => global_allow.push(c),
                Err(e) => errors.push(e),
            }
        }
        // dictionaries
        let mut dict_entries: Vec<DictEntryC> = Vec::new();
        for d in &def.dictionaries {
            if let Some(&ri) = by_id.get(&d.rule_id) {
                if !d.term.trim().is_empty() {
                    dict_entries.push(DictEntryC { rule_idx: ri, whole_word: d.whole_word, case_sensitive: d.case_sensitive, term: d.term.clone() });
                }
            }
        }
        // dictionary rules without regex are fine; rules with engine=dictionary were pushed with
        // empty `regexes` above only if they had patterns — handle: dictionary rules need no pattern
        if !errors.is_empty() {
            return Err(errors);
        }
        let dict_ac = if dict_entries.is_empty() {
            None
        } else {
            let pats: Vec<&str> = dict_entries.iter().map(|d| d.term.as_str()).collect();
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::LeftmostLongest)
                    .ascii_case_insensitive(true)
                    .build(&pats)
                    .map_err(|e| vec![RuleError { rule_id: "<dictionary>".into(), message: e.to_string() }])?,
            )
        };
        // keyword prefilter (gitleaks: aho-corasick over lowercased text)
        let mut kw_index: HashMap<String, usize> = HashMap::new();
        let mut kw_pats: Vec<String> = Vec::new();
        let mut kw_rules: Vec<Vec<usize>> = Vec::new();
        let mut no_kw_rules = Vec::new();
        for (i, r) in rules.iter().enumerate() {
            if r.keywords.is_empty() {
                no_kw_rules.push(i);
                continue;
            }
            for k in &r.keywords {
                let id = *kw_index.entry(k.clone()).or_insert_with(|| {
                    kw_pats.push(k.clone());
                    kw_rules.push(Vec::new());
                    kw_pats.len() - 1
                });
                if !kw_rules[id].contains(&i) {
                    kw_rules[id].push(i);
                }
            }
        }
        let kw_ac = if kw_pats.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .match_kind(MatchKind::Standard)
                    .ascii_case_insensitive(true)
                    .build(&kw_pats)
                    .map_err(|e| vec![RuleError { rule_id: "<keywords>".into(), message: e.to_string() }])?,
            )
        };
        // Hyperscan prefilter database (failure isolated per pattern; absence is not an error)
        let mut hs = None;
        if opts.use_hyperscan && !hs_patterns.is_empty() {
            match Hyperscan::compile(&hs_patterns) {
                Ok((db, rep)) => {
                    report.hs_active = true;
                    report.hs_version = db.version.clone();
                    for (pid, msg) in rep.failed {
                        let owner = hs_owner[pid];
                        report.hs_failed.push((rules[owner].id.clone(), msg));
                        for slot in rules[owner].hs_ids.iter_mut() {
                            if *slot == Some(pid) {
                                *slot = None;
                            }
                        }
                    }
                    hs = Some(db);
                }
                Err(e) => report.hs_error = Some(e),
            }
        }
        report.n_enabled = rules.len();
        // fingerprint of the definition (change detection / audit)
        let mut h = Sha256::new();
        // fingerprint = content only (the version number is assigned by the database, not content)
        let mut canon = def.clone();
        canon.version = 0;
        h.update(serde_json::to_vec(&canon).unwrap_or_default());
        report.compile_ms = t0.elapsed().as_millis();
        let dict_max_len = dict_entries.iter().map(|d| d.term.len()).max().unwrap_or(0);
        Ok(RuleSet { version: def.version, fingerprint: hex::encode(h.finalize()), rules, by_id, kw_ac, kw_rules, no_kw_rules, global_allow, dict_ac, dict_entries, dict_max_len, hs, report })
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
    pub fn hs_active(&self) -> bool {
        self.hs.is_some()
    }
    pub fn rule(&self, id: &str) -> Option<&CompiledRule> {
        self.by_id.get(id).map(|&i| &self.rules[i])
    }
    pub fn rules_iter(&self) -> impl Iterator<Item = &CompiledRule> {
        self.rules.iter()
    }
    pub fn has_dictionary(&self) -> bool {
        self.dict_ac.is_some()
    }

    /// Largest number of bytes a single entity of `group` can span (including context windows);
    /// `None` when any active rule is unbounded or depends on out-of-match text (line allowlists,
    /// required rules). Used by the streaming scanner to prove its hold-back window is sufficient.
    pub fn window_bound(&self, group: RuleGroup) -> Option<usize> {
        let mut m = 0usize;
        for r in self.rules.iter().filter(|r| r.group == Some(group)) {
            m = m.max(r.window_bound?);
        }
        Some(m)
    }

    /// Bound over every active detector family (patterns + secrets + dictionary).
    pub fn window_bound_all(&self) -> Option<usize> {
        let a = self.window_bound(RuleGroup::Pii)?;
        let b = self.window_bound(RuleGroup::Secret)?;
        Some(a.max(b).max(self.dict_max_len).max(1))
    }

    /// Rules that make a provable streaming window impossible (unbounded length, or dependence on text
    /// outside the match such as line-scoped allowlists / required rules).
    pub fn window_blockers(&self) -> Vec<String> {
        self.rules.iter().filter(|r| r.group.is_some() && r.window_bound.is_none()).map(|r| r.id.clone()).collect()
    }

    /// Scan `text` with all rules of `group`.
    pub fn scan(&self, text: &str, group: RuleGroup, opts: &ScanOptions) -> Vec<Entity> {
        let n = self.rules.len();
        let mut active = vec![false; n];
        // 1. keyword prefilter
        if opts.ignore_keywords {
            for (i, r) in self.rules.iter().enumerate() {
                active[i] = r.group == Some(group);
            }
        } else {
            for &i in &self.no_kw_rules {
                active[i] = true;
            }
            if let Some(ac) = &self.kw_ac {
                let mut seen = vec![false; self.kw_rules.len()];
                for m in ac.find_overlapping_iter(text) {
                    let p = m.pattern().as_usize();
                    if !seen[p] {
                        seen[p] = true;
                        for &ri in &self.kw_rules[p] {
                            active[ri] = true;
                        }
                    }
                }
            }
            for (i, r) in self.rules.iter().enumerate() {
                if r.group != Some(group) {
                    active[i] = false;
                }
            }
        }
        if !opts.entity_filter.is_empty() {
            for (i, r) in self.rules.iter().enumerate() {
                if active[i] && !opts.entity_filter.iter().any(|e| e == &r.entity_type) {
                    active[i] = false;
                }
            }
        }
        // 2. hyperscan candidate filter (sound: prefilter never yields false negatives)
        if opts.use_hs {
            if let Some(hs) = &self.hs {
                let mut hit = vec![false; hs.n_patterns];
                if hs.scan_candidates(text, &mut hit).is_ok() {
                    for (i, r) in self.rules.iter().enumerate() {
                        if !active[i] || r.hs_ids.is_empty() {
                            continue;
                        }
                        let any = r.hs_ids.iter().any(|id| match id {
                            Some(pid) => hit[*pid],
                            None => true, // pattern not in the HS db: must stay a candidate
                        });
                        if !any {
                            active[i] = false;
                        }
                    }
                }
            }
        }
        // 3. exact evaluation
        let ctx = ScanCtx { text, nl: OnceCell::new() };
        let mut all: Vec<(usize, Finding)> = Vec::new();
        for i in 0..n {
            if !active[i] {
                continue;
            }
            if let Some(d) = opts.deadline {
                if Instant::now() > d {
                    break;
                }
            }
            let r = &self.rules[i];
            if r.skip_report {
                continue;
            }
            let mut findings = self.run_rule(i, &ctx, opts);
            if !r.required.is_empty() {
                findings = self.apply_required(i, findings, &ctx, opts);
            }
            for f in findings {
                all.push((i, f));
            }
        }
        if group == RuleGroup::Secret {
            all = self.filter_generic(all, &ctx);
        }
        let mut out: Vec<Entity> = Vec::with_capacity(all.len());
        for (i, f) in &all {
            out.push(self.to_entity(&self.rules[*i], f, &ctx));
        }
        out
    }

    /// gitleaks `detect/utils.go: filter`: a *generic* rule finding is dropped when, on the same
    /// line, a non-generic rule found a secret that contains it (the specific rule takes precedence).
    fn filter_generic(&self, all: Vec<(usize, Finding)>, ctx: &ScanCtx) -> Vec<(usize, Finding)> {
        let is_generic = |i: usize| self.rules[i].id.to_ascii_lowercase().contains("generic");
        if !all.iter().any(|(i, _)| is_generic(*i)) {
            return all;
        }
        let lines: Vec<usize> = all.iter().map(|(_, f)| ctx.line_col(f.m_start).0).collect();
        let mut keep = vec![true; all.len()];
        for (a, (ia, fa)) in all.iter().enumerate() {
            if !is_generic(*ia) {
                continue;
            }
            let sa = &ctx.text[fa.start..fa.end];
            for (b, (ib, fb)) in all.iter().enumerate() {
                if ia != ib && lines[a] == lines[b] && !is_generic(*ib) && ctx.text[fb.start..fb.end].contains(sa) {
                    keep[a] = false;
                    break;
                }
            }
        }
        all.into_iter().zip(keep).filter(|(_, k)| *k).map(|(x, _)| x).collect()
    }

    /// Dictionary lookups (company / project / system names, custom confidential terms).
    pub fn scan_dictionary(&self, text: &str, opts: &ScanOptions) -> Vec<Entity> {
        let Some(ac) = &self.dict_ac else { return vec![] };
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        for m in ac.find_iter(text) {
            let e = &self.dict_entries[m.pattern().as_usize()];
            let (s, en) = (m.start(), m.end());
            if e.case_sensitive && &text[s..en] != e.term {
                continue;
            }
            let r = &self.rules[e.rule_idx];
            if !opts.entity_filter.is_empty() && !opts.entity_filter.iter().any(|x| x == &r.entity_type) {
                continue;
            }
            if e.whole_word {
                let is_w = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
                let first_ascii = bytes[s].is_ascii_alphanumeric();
                let last_ascii = bytes[en - 1].is_ascii_alphanumeric();
                if first_ascii && s > 0 && is_w(bytes[s - 1]) {
                    continue;
                }
                if last_ascii && en < bytes.len() && is_w(bytes[en]) {
                    continue;
                }
            }
            let mut ent = Entity::new(&r.entity_type, s, en, "dictionary", &r.id);
            ent.confidence = r.confidence;
            ent.risk_level = r.risk;
            ent.evidence = r.evidence;
            ent.category = r.category.clone();
            ent.priority = r.priority;
            ent.irreversible = r.irreversible;
            out.push(ent);
        }
        out
    }

    fn to_entity(&self, r: &CompiledRule, f: &Finding, ctx: &ScanCtx) -> Entity {
        let det = match r.group {
            Some(RuleGroup::Secret) => "secret",
            _ => {
                if self.hs.is_some() {
                    "hyperscan"
                } else {
                    "regex"
                }
            }
        };
        let mut e = Entity::new(&r.entity_type, f.start, f.end, det, &r.id);
        let mut conf = r.confidence;
        if let Some(c) = r.ctx.as_ref().filter(|c| !c.deny) {
            if self.context_hit(c, ctx.text, f.start, f.end) {
                conf = (conf + 0.1).min(0.99);
                e.metadata.insert("context".into(), "matched".into());
            }
        }
        e.confidence = conf;
        e.risk_level = r.risk;
        e.evidence = r.evidence;
        e.category = r.category.clone();
        e.priority = r.priority;
        e.irreversible = r.irreversible;
        if f.entropy > 0.0 {
            e.metadata.insert("entropy".into(), format!("{:.2}", f.entropy));
        }
        e
    }

    fn context_hit(&self, c: &ContextSpec, text: &str, start: usize, end: usize) -> bool {
        let lo = dlp_core::floor_char_boundary(text, start.saturating_sub(c.window));
        let hi = dlp_core::ceil_char_boundary(text, (end + c.window).min(text.len()));
        c.ac.is_match(&text[lo..start]) || c.ac.is_match(&text[end..hi])
    }

    /// One rule over one text. Mirrors gitleaks `detectRule` (content part).
    fn run_rule(&self, idx: usize, ctx: &ScanCtx, opts: &ScanOptions) -> Vec<Finding> {
        let r = &self.rules[idx];
        let text = ctx.text;
        let mut out = Vec::new();
        for re in &r.regexes {
            let mut pos = 0usize;
            while pos <= text.len() {
                let Some(m) = re.find_at(text, pos) else { break };
                // default: continue after the match (gitleaks FindAll semantics)
                pos = if m.end() > m.start() { m.end() } else { dlp_core::ceil_char_boundary(text, m.end() + 1).max(m.end() + 1) };
                // secret := strings.Trim(match, "\n")
                let raw = m.as_str();
                let lead = raw.len() - raw.trim_start_matches('\n').len();
                let trimmed = raw.trim_matches('\n');
                if trimmed.is_empty() {
                    continue;
                }
                let m_start = m.start() + lead;
                let m_end = m_start + trimmed.len();
                if !opts.honor_inline_allow {
                    // (deliberately NOT honouring `gitleaks:allow`)
                } else if ctx.line_text(m_start).contains("gitleaks:allow") {
                    continue;
                }
                // groups := r.Regex.FindStringSubmatch(finding.Secret)  — gitleaks re-matches on the substring
                let (mut s_start, mut s_end) = (m_start, m_end);
                if re.captures_len() >= 2 {
                    if let Some(caps) = re.captures(trimmed) {
                        let pick = if r.secret_group > 0 {
                            caps.get(r.secret_group).map(|g| (g.start(), g.end())).or(Some((0, 0)))
                        } else {
                            (1..caps.len()).filter_map(|gi| caps.get(gi)).find(|g| !g.as_str().is_empty()).map(|g| (g.start(), g.end()))
                        };
                        if let Some((gs, ge)) = pick {
                            s_start = m_start + gs;
                            s_end = m_start + ge;
                        }
                    }
                }
                let secret = &text[s_start..s_end];
                if secret.is_empty() {
                    continue;
                }
                if r.digit_boundary {
                    let b = text.as_bytes();
                    let touches = (m_start > 0 && b[m_start - 1].is_ascii_digit()) || b.get(m_end).is_some_and(|c| c.is_ascii_digit());
                    if touches {
                        // part of a longer digit run: nothing inside it can be a standalone number
                        let mut e = m_end;
                        while e < b.len() && b[e].is_ascii_digit() {
                            e += 1;
                        }
                        pos = pos.max(e);
                        continue;
                    }
                }
                let ent = shannon_entropy(secret);
                if r.entropy != 0.0 && ent <= r.entropy {
                    continue;
                }
                let whole = &text[m_start..m_end];
                if !r.validators.iter().all(|v| v.check(secret, whole)) {
                    // A validator rejection must not hide a valid match that starts inside this one
                    // (e.g. "员工马娟的…": the regex first matches "工马娟", the surname check fails, but
                    // "马娟" is valid). Retry from the next character. Only validators trigger this;
                    // entropy / allowlist rejections keep gitleaks' skip-the-whole-match behaviour.
                    pos = dlp_core::ceil_char_boundary(text, m.start() + 1).max(m.start() + 1);
                    continue;
                }
                let line_fn = || ctx.line_text(m_start).to_string();
                if self.global_allow.iter().any(|a| a.allows(secret, whole, &line_fn)) || r.allowlists.iter().any(|a| a.allows(secret, whole, &line_fn)) {
                    continue;
                }
                if let Some(c) = &r.ctx {
                    if c.require && !self.context_hit(c, text, s_start, s_end) {
                        continue;
                    }
                    if c.deny {
                        let lo = dlp_core::floor_char_boundary(text, s_start.saturating_sub(c.window));
                        if c.ac.is_match(&text[lo..s_start]) {
                            continue;
                        }
                    }
                }
                let (line, col) = if r.required.is_empty() && !opts.honor_inline_allow { (0, 0) } else { ctx.line_col(m_start) };
                out.push(Finding { m_start, start: s_start, end: s_end, entropy: ent, line, col });
            }
        }
        out
    }

    /// gitleaks `processRequiredRules`: keep a primary finding only if every required rule has at
    /// least one finding within the proximity limits.
    fn apply_required(&self, idx: usize, primary: Vec<Finding>, ctx: &ScanCtx, opts: &ScanOptions) -> Vec<Finding> {
        if primary.is_empty() {
            return primary;
        }
        let r = &self.rules[idx];
        let mut aux: Vec<(usize, Vec<Finding>)> = Vec::new();
        for q in &r.required {
            let mut fs = self.run_rule(q.rule_idx, ctx, opts);
            for f in fs.iter_mut() {
                let (l, c) = ctx.line_col(f.start);
                f.line = l;
                f.col = c;
            }
            aux.push((q.rule_idx, fs));
        }
        let mut out = Vec::new();
        'p: for mut p in primary {
            let (l, c) = ctx.line_col(p.start);
            p.line = l;
            p.col = c;
            for (qi, q) in r.required.iter().enumerate() {
                let ok = aux[qi].1.iter().any(|f| {
                    q.within_lines.map(|w| (p.line as i64 - f.line as i64).abs() <= w).unwrap_or(true)
                        && q.within_columns.map(|w| (p.col as i64 - f.col as i64).abs() <= w).unwrap_or(true)
                });
                if !ok {
                    continue 'p;
                }
            }
            out.push(p);
        }
        out
    }
}
