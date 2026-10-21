use dlp_rules::hyperscan::Hyperscan;
use std::time::Instant;
fn main() {
    let text = std::fs::read_to_string("third_party/gitleaks/config/gitleaks.toml").unwrap();
    let doc: toml::Value = toml::from_str(&text).unwrap();
    let mut v: Vec<(String, f64, usize)> = vec![];
    let mut total = 0.0;
    for r in doc["rules"].as_array().unwrap() {
        let Some(rx) = r.get("regex").and_then(|x| x.as_str()) else { continue };
        let id = r["id"].as_str().unwrap().to_string();
        let t = Instant::now();
        let res = Hyperscan::compile(&[(rx.to_string(), false)]);
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        total += ms;
        v.push((id, ms, if res.is_ok() { 1 } else { 0 }));
    }
    v.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    println!("sum of individual compiles: {:.0} ms for {} patterns", total, v.len());
    for (id, ms, ok) in v.iter().take(8) { println!("{ms:8.0} ms ok={ok} {id}"); }
    let pats: Vec<(String, bool)> = doc["rules"].as_array().unwrap().iter().filter_map(|r| r.get("regex").and_then(|x| x.as_str()).map(|s| (s.to_string(), false))).collect();
    let t = Instant::now();
    let r = Hyperscan::compile(&pats);
    println!("multi compile (incl. per-pattern isolation pass): {:.0} ms ok={}", t.elapsed().as_secs_f64() * 1000.0, r.is_ok());
}
