//! `dlp` – command line tool for the Unified AI DLP Engine.
//! By default raw sensitive values are never printed; use `--reveal` (debug) to see them.
use clap::{Parser, Subcommand};
use dlp_core::*;
use dlp_detectors::NlpConfig;
use dlp_engine::*;
use dlp_storage::{builtin, gitleaks, Store};
use std::io::Read;
use std::sync::Arc;
use std::time::Instant;

#[derive(Parser)]
#[command(name = "dlp", version, about = "Unified AI DLP Engine CLI")]
struct Cli {
    /// SQLite rule database
    #[arg(long, env = "DLP_DB", default_value = "ai_dlp.db", global = true)]
    db: String,
    /// directory with builtin.toml / gitleaks.toml (used by `init` and to bootstrap an empty DB)
    #[arg(long, env = "DLP_RULES_DIR", default_value = "rules", global = true)]
    rules_dir: String,
    /// NLP service URL (enables Presidio/GLiNER detectors), e.g. http://127.0.0.1:8791
    #[arg(long, env = "DLP_NLP_URL", global = true)]
    nlp_url: Option<String>,
    #[arg(long, env = "DLP_NLP_TOKEN", global = true, default_value = "")]
    nlp_token: String,
    /// disable the Hyperscan prefilter (portable regex path only)
    #[arg(long, global = true)]
    no_hyperscan: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// create the database and import gitleaks + built-in rules and policies
    Init,
    /// detect / sanitize / anonymize text
    Detect(DetectArgs),
    /// process a file with one text per line (or JSON lines with {"text":..}); prints a summary
    Batch(BatchArgs),
    /// show detector / ruleset status and capabilities
    Status,
    /// rule database management
    #[command(subcommand)]
    Rules(RulesCmd),
    /// quick throughput measurement (see benchmarks/ for the full suite)
    Bench(BenchArgs),
}

#[derive(clap::Args)]
struct DetectArgs {
    #[arg(short, long)]
    text: Option<String>,
    #[arg(short, long)]
    file: Option<String>,
    #[arg(short, long, default_value = "default")]
    policy: String,
    /// comma separated: regex,secret,dictionary,presidio,gliner
    #[arg(long)]
    detectors: Option<String>,
    #[arg(long, default_value = "request")]
    direction: String,
    /// detect | sanitize | anonymize
    #[arg(short, long, default_value = "detect")]
    mode: String,
    #[arg(long, default_value = "auto")]
    language: String,
    #[arg(long)]
    session: Option<String>,
    /// print matched values (debug)
    #[arg(long)]
    reveal: bool,
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
struct BatchArgs {
    file: String,
    #[arg(short, long, default_value = "default")]
    policy: String,
    #[arg(short, long, default_value = "detect")]
    mode: String,
    #[arg(long)]
    detectors: Option<String>,
}

#[derive(clap::Args)]
struct BenchArgs {
    #[arg(long, default_value_t = 1000)]
    bytes: usize,
    /// iterations (in-process mode) – ignored when --seconds is given
    #[arg(long, default_value_t = 2000)]
    iterations: usize,
    /// concurrent client threads
    #[arg(long, default_value_t = 1)]
    threads: usize,
    /// run for this many seconds instead of a fixed iteration count
    #[arg(long)]
    seconds: Option<u64>,
    #[arg(long, default_value = "regex,secret,dictionary")]
    detectors: String,
    #[arg(long, default_value = "rules-only")]
    policy: String,
    /// detect | sanitize | anonymize
    #[arg(long, default_value = "detect")]
    mode: String,
    /// benchmark a running dlp-server over HTTP instead of the in-process engine
    #[arg(long)]
    url: Option<String>,
    #[arg(long, env = "DLP_KEY", default_value = "")]
    key: String,
    /// batch size for /v1/detect/batch (HTTP mode only; 1 = single requests)
    #[arg(long, default_value_t = 1)]
    batch: usize,
    /// emit one JSON object (for benchmarks/perf/run_perf.py)
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum RulesCmd {
    ImportGitleaks { file: String, #[arg(long, default_value = "")] source_version: String, #[arg(long, default_value = "")] commit: String },
    ImportBuiltin { file: String },
    List { #[arg(long)] source: Option<String> },
    Versions,
    Rollback { version: i64 },
    Reload,
    Enable { id: String },
    Disable { id: String },
    /// add terms to a dictionary rule (e.g. dict-project)
    AddTerms { rule_id: String, terms: Vec<String> },
    Audit { #[arg(default_value_t = 20)] n: usize },
}

fn engine_cfg(cli: &Cli) -> EngineConfig {
    let mut cfg = EngineConfig::default();
    cfg.db_path = cli.db.clone();
    cfg.rules_dir = Some(cli.rules_dir.clone());
    cfg.use_hyperscan = !cli.no_hyperscan;
    if let Some(u) = &cli.nlp_url {
        cfg.nlp = Some(NlpConfig { base_url: u.trim_end_matches('/').to_string(), token: cli.nlp_token.clone(), ..Default::default() });
    }
    cfg
}

fn mode_of(s: &str) -> Mode {
    match s {
        "sanitize" => Mode::Sanitize,
        "anonymize" => Mode::Anonymize,
        _ => Mode::Detect,
    }
}

fn read_input(text: &Option<String>, file: &Option<String>) -> String {
    if let Some(t) = text {
        return t.clone();
    }
    if let Some(f) = file {
        let s = std::fs::read_to_string(f).unwrap_or_else(|e| {
            eprintln!("cannot read {f} as UTF-8: {e}");
            std::process::exit(2)
        });
        // Windows editors often write a UTF-8 BOM
        return s.strip_prefix('\u{feff}').map(String::from).unwrap_or(s);
    }
    let mut s = String::new();
    let _ = std::io::stdin().read_to_string(&mut s);
    s.strip_prefix('\u{feff}').map(String::from).unwrap_or(s)
}

fn main() {
    let cli = Cli::parse();
    let caller = Caller::local_admin();
    match &cli.cmd {
        Cmd::Init => {
            let store = Store::open(&cli.db).unwrap_or_else(die);
            let gl = format!("{}/gitleaks.toml", cli.rules_dir);
            if let Ok(t) = std::fs::read_to_string(&gl) {
                let r = gitleaks::import_gitleaks_toml(&store, &t, &gitleaks::ImportMeta { source_version: "v8-main".into(), source_commit: "b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b".into() }).unwrap_or_else(die);
                println!("gitleaks: total={} inserted={} updated={} unchanged={} unsupported={} path_only={}", r.total, r.inserted, r.updated, r.unchanged, r.unsupported, r.path_only);
            }
            let t = std::fs::read_to_string(format!("{}/builtin.toml", cli.rules_dir)).unwrap_or_else(die);
            let r = builtin::import_builtin_toml(&store, &t).unwrap_or_else(die);
            println!("builtin: inserted={} updated={} unchanged={} dictionary_terms={} policies={}", r.rules_inserted, r.rules_updated, r.rules_unchanged, r.dictionary_terms, r.policies);
            println!("database ready: {} (schema v{})", cli.db, store.schema_version().unwrap_or(0));
        }
        Cmd::Detect(a) => {
            let eng = DlpEngine::open(engine_cfg(&cli)).unwrap_or_else(die);
            let text = read_input(&a.text, &a.file);
            let mut req = DetectRequest::new(&text);
            req.policy_id = Some(a.policy.clone());
            req.direction = Direction::parse(&a.direction).unwrap_or(Direction::Request);
            req.mode = Some(mode_of(&a.mode));
            req.language = a.language.clone();
            req.session_id = a.session.clone();
            req.reveal_values = a.reveal;
            req.detectors = a.detectors.as_ref().map(|d| d.split(',').map(|s| s.trim().to_string()).collect());
            match eng.process(&caller, &req) {
                Ok(r) => {
                    if a.json {
                        println!("{}", serde_json::to_string_pretty(&r).unwrap());
                    } else {
                        print_human(&r, a.reveal);
                    }
                    if r.decision == Verdict::Blocked {
                        std::process::exit(3);
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Batch(a) => {
            let eng = DlpEngine::open(engine_cfg(&cli)).unwrap_or_else(die);
            let content = std::fs::read_to_string(&a.file).unwrap_or_else(die);
            let texts: Vec<String> = content.lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str::<serde_json::Value>(l).ok().and_then(|v| v.get("text").and_then(|t| t.as_str().map(String::from))).unwrap_or_else(|| l.to_string())).collect();
            let mut by_type: std::collections::BTreeMap<String, usize> = Default::default();
            let (mut blocked, mut modified, mut allow, mut degraded) = (0, 0, 0, 0);
            let t0 = Instant::now();
            for chunk in texts.chunks(eng.cfg.limits.max_batch) {
                let reqs: Vec<DetectRequest> = chunk.iter().map(|t| {
                    let mut r = DetectRequest::new(t);
                    r.policy_id = Some(a.policy.clone());
                    r.mode = Some(mode_of(&a.mode));
                    r.detectors = a.detectors.as_ref().map(|d| d.split(',').map(|s| s.trim().to_string()).collect());
                    r
                }).collect();
                for r in eng.process_many(&caller, &reqs) {
                    match r {
                        Ok(r) => {
                            match r.decision {
                                Verdict::Blocked => blocked += 1,
                                Verdict::Modified => modified += 1,
                                Verdict::Allow => allow += 1,
                            }
                            degraded += r.degraded as usize;
                            for e in r.entities {
                                *by_type.entry(e.entity_type).or_default() += 1;
                            }
                        }
                        Err(e) => eprintln!("item error: {e}"),
                    }
                }
            }
            println!("{} texts in {:.1} ms: allow={allow} modified={modified} blocked={blocked} degraded={degraded}", texts.len(), t0.elapsed().as_secs_f64() * 1000.0);
            for (k, v) in by_type {
                println!("  {k:24} {v}");
            }
        }
        Cmd::Status => {
            let eng = DlpEngine::open(engine_cfg(&cli)).unwrap_or_else(die);
            println!("{}", serde_json::to_string_pretty(&eng.capabilities()).unwrap());
        }
        Cmd::Rules(rc) => rules_cmd(&cli, rc, &caller),
        Cmd::Bench(b) => bench(&cli, b, &caller),
    }
}

fn die<E: std::fmt::Display, T>(e: E) -> T {
    eprintln!("error: {e}");
    std::process::exit(1)
}

fn print_human(r: &DetectResponse, reveal: bool) {
    println!("decision: {:?}  policy: {}  ruleset: v{}  time: {:.2} ms{}", r.decision, r.policy_id, r.ruleset_version, r.processing_time_ms, if r.degraded { "  [DEGRADED]" } else { "" });
    if let Some(b) = &r.blocked_reason {
        println!("blocked: {b}");
    }
    for d in &r.detector_status {
        if d.enabled {
            println!("  detector {:10} {:?}{}{}", d.name, d.state, if d.ran { format!("  ran {:.2} ms", d.ms) } else { String::new() }, d.error.as_ref().map(|e| format!("  ERROR: {e}")).unwrap_or_default());
        }
    }
    for w in &r.warnings {
        println!("  warning: {w}");
    }
    println!("entities ({}):", r.entities.len());
    for e in &r.entities {
        println!("  {:22} [{:>4},{:>4}) conf={:.2} risk={:<8} {:9} -> {:9} rule={} {}{}", e.entity_type, e.start, e.end, e.confidence, e.risk_level.as_str(), e.detector, e.action.as_str(), e.rule_id, e.replacement.as_deref().map(|x| format!("repl={x} ")).unwrap_or_default(), if reveal { format!("value={:?}", e.value.clone().unwrap_or_default()) } else { String::new() });
    }
    if let Some(t) = &r.sanitized_text {
        println!("sanitized: {t}");
    }
    if let Some(s) = &r.session_id {
        println!("session_id: {s}");
    }
}

fn rules_cmd(cli: &Cli, rc: &RulesCmd, caller: &Caller) {
    match rc {
        RulesCmd::ImportGitleaks { file, source_version, commit } => {
            let store = Store::open(&cli.db).unwrap_or_else(die);
            let t = std::fs::read_to_string(file).unwrap_or_else(die);
            let r = gitleaks::import_gitleaks_toml(&store, &t, &gitleaks::ImportMeta { source_version: source_version.clone(), source_commit: commit.clone() }).unwrap_or_else(die);
            println!("{}", serde_json::to_string_pretty(&r).unwrap());
        }
        RulesCmd::ImportBuiltin { file } => {
            let store = Store::open(&cli.db).unwrap_or_else(die);
            let t = std::fs::read_to_string(file).unwrap_or_else(die);
            let r = builtin::import_builtin_toml(&store, &t).unwrap_or_else(die);
            println!("{}", serde_json::to_string_pretty(&r).unwrap());
        }
        RulesCmd::List { source } => {
            let store = Store::open(&cli.db).unwrap_or_else(die);
            let d = store.load_ruleset_def().unwrap_or_else(die);
            for r in d.rules.iter().filter(|r| source.as_ref().map(|s| &r.source == s).unwrap_or(true)) {
                println!("{:<42} {:<10} {:<22} {:<8} {} {}", r.id, r.engine, r.entity_type, r.risk_level, if r.enabled { "on " } else { "off" }, r.compat);
            }
            println!("{} rules, {} dictionary terms", d.rules.len(), d.dictionaries.len());
        }
        RulesCmd::Versions => {
            let store = Store::open(&cli.db).unwrap_or_else(die);
            for v in store.list_versions().unwrap_or_else(die) {
                println!("v{:<4} {} {} {}", v.version, if v.active { "*" } else { " " }, v.created_at, v.reason);
            }
        }
        RulesCmd::Audit { n } => {
            let store = Store::open(&cli.db).unwrap_or_else(die);
            for (id, ts, t, op, key) in store.audit_tail(*n).unwrap_or_else(die) {
                println!("#{id} {ts} {t} {op} {key}");
            }
        }
        RulesCmd::Enable { id } | RulesCmd::Disable { id } => {
            let store = Store::open(&cli.db).unwrap_or_else(die);
            let on = matches!(rc, RulesCmd::Enable { .. });
            println!("{}", if store.set_rule_enabled(id, on).unwrap_or_else(die) { "ok (run `dlp rules reload` in a running server via POST /v1/rules/reload)" } else { "no such rule" });
        }
        RulesCmd::AddTerms { rule_id, terms } => {
            let store = Store::open(&cli.db).unwrap_or_else(die);
            println!("added {} term(s)", store.add_dictionary_terms(rule_id, terms).unwrap_or_else(die));
        }
        RulesCmd::Reload => {
            let eng = DlpEngine::open(engine_cfg(cli)).unwrap_or_else(die);
            println!("{}", serde_json::to_string_pretty(&eng.reload_rules(caller).unwrap_or_else(die)).unwrap());
        }
        RulesCmd::Rollback { version } => {
            let eng = DlpEngine::open(engine_cfg(cli)).unwrap_or_else(die);
            println!("{}", serde_json::to_string_pretty(&eng.rollback_rules(caller, *version).unwrap_or_else(die)).unwrap());
        }
    }
}

fn bench(cli: &Cli, b: &BenchArgs, caller: &Caller) {
    let seed = "联系人：张三，手机13800138000，邮箱 zhangsan@example.com，aws_key=AKIAZ3XQKVN5TLWM7EPD，身份证11010119900307002X，内网 192.168.1.20。日常聊天内容：今天的会议安排在下午三点，请大家准时参加。Please contact Alice Johnson at alice@example.com about the Acme Corporation invoice. ";
    let mut text = String::new();
    while text.len() < b.bytes {
        text.push_str(seed);
    }
    let text = text[..dlp_core::floor_char_boundary(&text, b.bytes)].to_string();
    let dets: Vec<String> = b.detectors.split(',').map(|s| s.trim().to_string()).collect();
    let stop_at = b.seconds.map(|s| Instant::now() + std::time::Duration::from_secs(s));
    let per = b.iterations / b.threads.max(1);
    let engine: Option<Arc<DlpEngine>> = if b.url.is_none() { Some(DlpEngine::open(engine_cfg(cli)).unwrap_or_else(die)) } else { None };
    let agent = ureq::AgentBuilder::new().max_idle_connections_per_host(b.threads + 4).timeout(std::time::Duration::from_secs(120)).build();
    let single = serde_json::json!({"text": text, "policy_id": b.policy, "detectors": dets, "mode": b.mode}).to_string();
    let batch_body = if b.batch > 1 { Some(serde_json::json!({"items": (0..b.batch).map(|_| serde_json::json!({"text": text, "detectors": dets})).collect::<Vec<_>>(), "policy_id": b.policy, "mode": b.mode}).to_string()) } else { None };
    let (lat, errs, degraded, shed) = (std::sync::Mutex::new(Vec::<f64>::new()), std::sync::atomic::AtomicUsize::new(0), std::sync::atomic::AtomicUsize::new(0), std::sync::atomic::AtomicUsize::new(0));
    let t0 = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..b.threads {
            s.spawn(|| {
                let mut local = Vec::new();
                let mut i = 0usize;
                loop {
                    match stop_at {
                        Some(t) => {
                            if Instant::now() >= t {
                                break;
                            }
                        }
                        None => {
                            if i >= per {
                                break;
                            }
                        }
                    }
                    i += 1;
                    let t = Instant::now();
                    if let Some(url) = &b.url {
                        let (path, body) = match &batch_body {
                            Some(bb) => ("/v1/detect/batch", bb.as_str()),
                            None => ("/v1/detect", single.as_str()),
                        };
                        match agent.post(&format!("{url}{path}")).set("Authorization", &format!("Bearer {}", b.key)).set("Content-Type", "application/json").send_string(body) {
                            Ok(r) => {
                                let txt = r.into_string().unwrap_or_default();
                                if txt.contains("\"degraded\":true") {
                                    degraded.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                            Err(ureq::Error::Status(503, _)) => {
                                shed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(_) => {
                                errs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    } else {
                        let mut r = DetectRequest::new(&text);
                        r.policy_id = Some(b.policy.clone());
                        r.detectors = Some(dets.clone());
                        r.mode = Some(mode_of(&b.mode));
                        match engine.as_ref().unwrap().process(caller, &r) {
                            Ok(x) => {
                                if x.degraded {
                                    degraded.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                }
                            }
                            Err(_) => {
                                errs.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                    local.push(t.elapsed().as_secs_f64() * 1000.0);
                }
                lat.lock().unwrap().extend(local);
            });
        }
    });
    let el = t0.elapsed().as_secs_f64();
    let mut l = lat.into_inner().unwrap();
    l.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if l.is_empty() {
        println!("no requests completed");
        return;
    }
    let p = |q: f64| l[((l.len() as f64 * q) as usize).min(l.len() - 1)];
    let items = b.batch.max(1);
    let (e, d, sh) = (errs.load(std::sync::atomic::Ordering::Relaxed), degraded.load(std::sync::atomic::Ordering::Relaxed), shed.load(std::sync::atomic::Ordering::Relaxed));
    let mean = l.iter().sum::<f64>() / l.len() as f64;
    if b.json {
        println!("{}", serde_json::json!({"bytes": b.bytes, "threads": b.threads, "detectors": b.detectors, "mode": b.mode, "transport": if b.url.is_some() {"http"} else {"in-process"}, "batch": items, "requests": l.len(), "seconds": el, "qps": l.len() as f64 / el, "items_per_s": (l.len() * items) as f64 / el, "mean_ms": mean, "p50_ms": p(0.5), "p95_ms": p(0.95), "p99_ms": p(0.99), "max_ms": l[l.len()-1], "errors": e, "degraded_responses": d, "shed_503": sh}));
    } else {
        println!("{} bytes={} threads={} detectors={} mode={} n={} qps={:.0} mean={:.3}ms p50={:.3} p95={:.3} p99={:.3} errors={e} degraded={d} shed503={sh}", if b.url.is_some() {"http"} else {"in-proc"}, b.bytes, b.threads, b.detectors, b.mode, l.len(), l.len() as f64 / el, mean, p(0.5), p(0.95), p(0.99));
    }
}
