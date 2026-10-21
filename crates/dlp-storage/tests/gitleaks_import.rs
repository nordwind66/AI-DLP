use dlp_rules::*;
use dlp_storage::gitleaks::*;
use dlp_storage::Store;

fn gitleaks_toml() -> Option<String> {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../third_party/gitleaks/config/gitleaks.toml")).ok()
}

#[test]
fn import_real_default_config_and_compile() {
    let Some(text) = gitleaks_toml() else {
        eprintln!("third_party/gitleaks not present; skipping");
        return;
    };
    let store = Store::open_in_memory().unwrap();
    let meta = ImportMeta { source_version: "v8.30-test".into(), source_commit: "b58d3f1".into() };
    let rep = import_gitleaks_toml(&store, &text, &meta).unwrap();
    println!("{}", serde_json::to_string_pretty(&rep).unwrap());
    assert_eq!(rep.total, 222);
    assert_eq!(rep.inserted, 222);
    // re-import is idempotent
    let rep2 = import_gitleaks_toml(&store, &text, &meta).unwrap();
    assert_eq!(rep2.inserted, 0);
    assert_eq!(rep2.unchanged, 222);
    // everything importable must compile as a RuleSet (with and without hyperscan)
    let def = store.load_ruleset_def().unwrap();
    for hs in [false, true] {
        let rs = RuleSet::compile(&def, &CompileOptions { use_hyperscan: hs }).unwrap_or_else(|e| panic!("compile errors: {:?}", e.iter().map(|x| x.to_string()).collect::<Vec<_>>()));
        println!("hs={hs}: enabled={} hs_active={} hs_failed={} path_only={:?} compile_ms={}", rs.report.n_enabled, rs.report.hs_active, rs.report.hs_failed.len(), rs.report.path_only_skipped, rs.report.compile_ms);
        if hs && rs.report.hs_active {
            for (id, m) in rs.report.hs_failed.iter().take(10) {
                println!("  hs-reject {id}: {m}");
            }
        }
    }
}
