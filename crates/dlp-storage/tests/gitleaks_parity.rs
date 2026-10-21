//! Differential test: the Rust SecretDetector vs the real gitleaks binary (commit b58d3f1) over
//! the 6289 unique TP/FP samples that gitleaks' own rule generator uses (tests/data/*.json).
//! Expected findings were produced by `scripts/gen_gitleaks_expected.sh` (upstream detector with
//! decoding disabled, default config).
use dlp_core::*;
use dlp_rules::*;
use dlp_storage::gitleaks::*;
use dlp_storage::Store;
use serde_json::Value;
use std::collections::BTreeSet;

fn read(p: &str) -> Option<String> {
    std::fs::read_to_string(format!("{}/../../{}", env!("CARGO_MANIFEST_DIR"), p)).ok()
}

#[test]
fn parity_with_upstream_gitleaks() {
    let (Some(cfg), Some(corpus), Some(expected)) = (read("third_party/gitleaks/config/gitleaks.toml"), read("tests/data/gitleaks_corpus.json"), read("tests/data/gitleaks_expected.json")) else {
        eprintln!("\n*** PARITY TEST SKIPPED: oracle fixtures are generated, not committed. Run: scripts/prepare_test_data.sh --gitleaks ***\n");
        return;
    };
    let store = Store::open_in_memory().unwrap();
    import_gitleaks_toml(&store, &cfg, &ImportMeta { source_version: "test".into(), source_commit: "b58d3f1".into() }).unwrap();
    let def = store.load_ruleset_def().unwrap();
    let rs = RuleSet::compile(&def, &CompileOptions { use_hyperscan: true }).unwrap();
    let handle = new_handle(rs);
    let det = RuleDetector::secret(handle);

    let corpus: Value = serde_json::from_str(&corpus).unwrap();
    let samples: Vec<&str> = corpus["samples"].as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect();
    let expected: Value = serde_json::from_str(&expected).unwrap();
    assert_eq!(samples.len(), expected.as_array().unwrap().len());

    let ctx = DetectContext::default();
    let (mut same, mut diff) = (0usize, 0usize);
    let mut report: Vec<String> = vec![];
    for (i, s) in samples.iter().enumerate() {
        let up: BTreeSet<(String, String)> = expected[i].as_array().unwrap().iter().map(|f| (f["rule"].as_str().unwrap().to_string(), f["secret"].as_str().unwrap().to_string())).collect();
        let ours: BTreeSet<(String, String)> = det.detect(&ctx, s).unwrap().into_iter().map(|e| (e.rule_id, s[e.start..e.end].to_string())).collect();
        if up == ours {
            same += 1;
        } else {
            diff += 1;
            if report.len() < 25 {
                let only_up: Vec<_> = up.difference(&ours).map(|(r, _)| r.clone()).collect();
                let only_ours: Vec<_> = ours.difference(&up).map(|(r, _)| r.clone()).collect();
                report.push(format!("#{i} upstream-only={only_up:?} ours-only={only_ours:?}"));
            }
        }
    }
    println!("PARITY: identical={same} different={diff} of {}", samples.len());
    for r in &report {
        println!("  {r}");
    }
    // Hard gate: fewer than 0.5% of samples may differ, and every difference must be explained in
    // docs/GITLEAKS_PARITY.md (decoding passes are out of scope for this comparison).
    assert!(diff * 200 < samples.len(), "parity gate failed: {diff} different of {}", samples.len());
}
