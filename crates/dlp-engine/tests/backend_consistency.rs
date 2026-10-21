//! Hyperscan is only a prefilter: with and without it (the Windows / no-libhs path) the engine must
//! return exactly the same entities. Checked over the whole accuracy dataset + the gitleaks corpus.
mod common;
use common::*;
use dlp_core::*;
use dlp_engine::*;

fn ensure_dataset() {
    let root = format!("{}/../..", env!("CARGO_MANIFEST_DIR"));
    if !std::path::Path::new(&format!("{root}/tests/data/accuracy/dataset.jsonl")).exists() {
        // generated, not committed (see scripts/prepare_test_data.sh)
        let st = std::process::Command::new("python3").arg(format!("{root}/tests/data/accuracy/build_dataset.py")).status();
        assert!(st.map(|s| s.success()).unwrap_or(false), "cannot generate the accuracy dataset (python3 needed)");
    }
}

fn lines(p: &str) -> Vec<String> {
    std::fs::read_to_string(format!("{}/../../{p}", env!("CARGO_MANIFEST_DIR"))).map(|s| s.lines().map(String::from).collect()).unwrap_or_default()
}

#[test]
fn hyperscan_and_portable_backends_agree() {
    ensure_dataset();
    let with_hs = engine_with(|c| c.use_hyperscan = true);
    let without = engine_with(|c| c.use_hyperscan = false);
    if !with_hs.ruleset().hs_active() {
        eprintln!("libhs not available on this host: nothing to compare");
        return;
    }
    assert!(!without.ruleset().hs_active());
    let mut texts: Vec<String> = lines("tests/data/accuracy/dataset.jsonl").iter().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter_map(|v| v["text"].as_str().map(String::from)).collect();
    let corpus: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(format!("{}/../../tests/data/gitleaks_corpus.json", env!("CARGO_MANIFEST_DIR"))).unwrap_or_else(|_| "{\"samples\":[]}".into())).unwrap();
    texts.extend(corpus["samples"].as_array().unwrap().iter().filter_map(|s| s.as_str().map(String::from)).take(1500));
    assert!(texts.len() > 600, "dataset missing");
    let key = |r: &DetectResponse| r.entities.iter().map(|e| (e.byte_start, e.byte_end, e.rule_id.clone(), e.entity_type.clone())).collect::<Vec<_>>();
    let mut n_ent = 0;
    for chunk in texts.chunks(32) {
        let reqs: Vec<DetectRequest> = chunk.iter().map(|t| req(t, "audit-only", Mode::Detect)).collect();
        let a = with_hs.process_many(&admin(), &reqs);
        let b = without.process_many(&admin(), &reqs);
        for ((x, y), t) in a.into_iter().zip(b).zip(chunk) {
            let (x, y) = (x.unwrap(), y.unwrap());
            assert_eq!(key(&x), key(&y), "backends disagree on a text of {} bytes", t.len());
            n_ent += x.entities.len();
        }
    }
    assert!(n_ent > 500);
    eprintln!("hyperscan vs portable: {} texts, {} entities, identical", texts.len(), n_ent);
}
