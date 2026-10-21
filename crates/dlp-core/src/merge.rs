//! Multi-detector result merging.
//!
//! Design (see docs/ARCHITECTURE.md §merge):
//!  1. Exact/near-identical spans of the same type from different detectors are *fused*:
//!     the strongest evidence class wins, confidence is combined with a capped noisy-OR only
//!     across independent detector families, never averaged.
//!  2. Overlapping same-type spans of the same evidence class are *unioned* (LLM Guard does the
//!     same in `_remove_conflicts_and_get_text_manipulation_data`, step 1).
//!  3. Cross-type overlaps are resolved greedily by (evidence, rule priority, risk, confidence,
//!     length). A losing model entity that only partially overlaps a winner is *trimmed* to its
//!     remaining part (LLM Guard step 3) when enough characters remain; losing deterministic
//!     entities are dropped, because their span is exact and trimming would be meaningless.
use crate::types::*;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct MergeConfig {
    /// Detector name -> priority bonus used on ties (higher wins).
    pub detector_priority: HashMap<String, i32>,
    /// Minimum UTF-8 bytes a trimmed remainder must keep (2 CJK chars = 6 bytes).
    pub min_trim_bytes: usize,
    /// Upper bound for fused confidence.
    pub fusion_cap: f32,
    /// Boost applied when an independent model corroborates a deterministic hit.
    pub corroboration_boost: f32,
}

impl Default for MergeConfig {
    fn default() -> Self {
        MergeConfig {
            detector_priority: HashMap::new(),
            min_trim_bytes: 4,
            fusion_cap: 0.99,
            corroboration_boost: 0.05,
        }
    }
}

/// Detector family: the same family never corroborates itself (regex+hyperscan are one family).
fn family(detector: &str) -> &str {
    match detector {
        "regex" | "hyperscan" | "secret" | "dictionary" => "rules",
        d => d,
    }
}

fn rank_key(e: &Entity, cfg: &MergeConfig) -> (Evidence, i32, RiskLevel, u32, usize) {
    let dp = cfg.detector_priority.get(&e.detector).copied().unwrap_or(0);
    (e.evidence, e.priority + dp, e.risk_level, (e.confidence * 1000.0) as u32, e.len())
}

pub fn merge_entities(mut cands: Vec<Entity>, cfg: &MergeConfig) -> Vec<Entity> {
    cands.retain(|e| !e.is_empty());
    if cands.len() <= 1 {
        return cands;
    }
    // ---- 1 + 2: fuse / union same-type overlaps -------------------------------------------
    cands.sort_by(|a, b| a.entity_type.cmp(&b.entity_type).then(a.start.cmp(&b.start)).then(b.end.cmp(&a.end)));
    let mut fused: Vec<Entity> = Vec::with_capacity(cands.len());
    for c in cands {
        if let Some(last) = fused.last_mut() {
            if last.entity_type == c.entity_type && last.overlaps(&c) && fusable(last, &c) {
                fuse_into(last, c, cfg);
                continue;
            }
        }
        fused.push(c);
    }
    // ---- 3: cross-type conflict resolution --------------------------------------------------
    let mut order: Vec<usize> = (0..fused.len()).collect();
    order.sort_by(|&a, &b| rank_key(&fused[b], cfg).cmp(&rank_key(&fused[a], cfg)));
    let mut selected: Vec<Entity> = Vec::with_capacity(fused.len());
    for i in order {
        let mut cand = fused[i].clone();
        let mut dropped = false;
        // Iterate until the candidate no longer overlaps any selected entity.
        loop {
            let hit = selected.iter().find(|s| s.overlaps(&cand));
            match hit {
                None => break,
                Some(w) => {
                    if cand.evidence == Evidence::Model && !w.contains(&cand) && !cand.contains(w) {
                        // partial overlap: keep the larger remaining side
                        let left = w.start.saturating_sub(cand.start).min(cand.len());
                        let right = cand.end.saturating_sub(w.end).min(cand.len());
                        if w.start > cand.start && left >= right && left >= cfg.min_trim_bytes {
                            cand.end = w.start;
                        } else if cand.end > w.end && right >= cfg.min_trim_bytes {
                            cand.start = w.end;
                        } else {
                            dropped = true;
                            break;
                        }
                        cand.confidence *= 0.9;
                        cand.metadata.insert("trimmed".into(), "true".into());
                    } else if cand.evidence == Evidence::Model && cand.contains(w) && !w.contains(&cand) {
                        // model entity engulfs a winner: keep the bigger remaining side
                        let left = w.start - cand.start;
                        let right = cand.end - w.end;
                        if left >= right && left >= cfg.min_trim_bytes {
                            cand.end = w.start;
                        } else if right >= cfg.min_trim_bytes {
                            cand.start = w.end;
                        } else {
                            dropped = true;
                            break;
                        }
                        cand.confidence *= 0.9;
                        cand.metadata.insert("trimmed".into(), "true".into());
                    } else {
                        dropped = true;
                        break;
                    }
                }
            }
        }
        if !dropped && !cand.is_empty() {
            selected.push(cand);
        }
    }
    selected.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    selected
}

/// Adjacent entities of the same (name-like) type separated only by spaces become one entity.
/// Port of LLM Guard `Anonymize._merge_entities_with_whitespace_between`
/// (llm_guard/input_scanners/anonymize.py:213), restricted to types where this is meaningful.
pub fn merge_adjacent_same_type(mut ents: Vec<Entity>, text: &str) -> Vec<Entity> {
    const MERGEABLE: [&str; 4] = ["PERSON", "ORGANIZATION", "ADDRESS", "LOCATION"];
    ents.sort_by_key(|e| e.start);
    let mut out: Vec<Entity> = Vec::with_capacity(ents.len());
    for e in ents {
        if let Some(prev) = out.last_mut() {
            if prev.entity_type == e.entity_type
                && MERGEABLE.contains(&e.entity_type.as_str())
                && e.start >= prev.end
                && e.start - prev.end <= 1
                && text[prev.end..e.start].bytes().all(|b| b == b' ')
                && prev.action == e.action
            {
                prev.end = e.end;
                prev.confidence = prev.confidence.min(e.confidence);
                prev.metadata.insert("merged_adjacent".into(), "true".into());
                continue;
            }
        }
        out.push(e);
    }
    out
}

fn fusable(a: &Entity, b: &Entity) -> bool {
    // Same type, overlapping. Union only if the evidence class matches or the overlap is large.
    if a.evidence == b.evidence {
        return true;
    }
    let inter = a.end.min(b.end).saturating_sub(a.start.max(b.start));
    let shorter = a.len().min(b.len());
    inter * 2 >= shorter
}

fn fuse_into(acc: &mut Entity, other: Entity, cfg: &MergeConfig) {
    let diff_family = family(&acc.detector) != family(&other.detector);
    // Winner determines identity (detector/rule/action/risk); span is the union only when the
    // evidence class is equal, otherwise the stronger evidence's exact span is kept.
    let acc_key = rank_key(acc, cfg);
    let oth_key = rank_key(&other, cfg);
    let (mut winner, loser) = if oth_key > acc_key { (other, acc.clone()) } else { (acc.clone(), other) };
    if winner.evidence == loser.evidence {
        winner.start = winner.start.min(loser.start);
        winner.end = winner.end.max(loser.end);
    }
    let mut conf = winner.confidence.max(loser.confidence);
    if diff_family && winner.evidence != Evidence::Model {
        // independent corroboration: capped noisy-OR, never an average
        let noisy = 1.0 - (1.0 - winner.confidence) * (1.0 - loser.confidence * 0.5);
        conf = conf.max(noisy.min(winner.confidence + cfg.corroboration_boost));
    } else if diff_family {
        conf = 1.0 - (1.0 - winner.confidence) * (1.0 - loser.confidence);
    }
    winner.confidence = conf.min(cfg.fusion_cap);
    if winner.risk_level < loser.risk_level {
        winner.risk_level = loser.risk_level;
    }
    let sources = format!(
        "{},{}",
        winner.metadata.get("sources").cloned().unwrap_or_else(|| winner.detector.clone()),
        loser.metadata.get("sources").cloned().unwrap_or_else(|| loser.detector.clone())
    );
    let mut uniq: Vec<&str> = sources.split(',').collect();
    uniq.sort();
    uniq.dedup();
    let joined = uniq.join(",");
    winner.metadata.insert("sources".into(), joined);
    *acc = winner;
}

#[cfg(test)]
mod tests {
    use super::*;
    fn e(t: &str, s: usize, en: usize, det: &str, ev: Evidence, conf: f32) -> Entity {
        let mut x = Entity::new(t, s, en, det, "r");
        x.evidence = ev;
        x.confidence = conf;
        x
    }
    #[test]
    fn deterministic_beats_model_on_cross_type_overlap() {
        let out = merge_entities(
            vec![
                e("PHONE_NUMBER", 10, 21, "regex", Evidence::Validated, 0.9),
                e("ORGANIZATION", 4, 21, "gliner", Evidence::Model, 0.97),
            ],
            &MergeConfig::default(),
        );
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].entity_type, "ORGANIZATION");
        assert_eq!((out[0].start, out[0].end), (4, 10)); // trimmed
        assert_eq!(out[1].entity_type, "PHONE_NUMBER");
    }
    #[test]
    fn same_span_same_type_fused_not_averaged() {
        let out = merge_entities(
            vec![
                e("EMAIL_ADDRESS", 0, 10, "regex", Evidence::Validated, 0.9),
                e("EMAIL_ADDRESS", 0, 10, "presidio", Evidence::Model, 0.5),
            ],
            &MergeConfig::default(),
        );
        assert_eq!(out.len(), 1);
        assert!(out[0].confidence >= 0.9 && out[0].confidence <= 0.99);
        assert_eq!(out[0].detector, "regex");
        assert!(out[0].metadata["sources"].contains("presidio"));
    }
    #[test]
    fn adjacent_names_merge_but_not_across_other_text() {
        let text = "Alice Johnson and Bob";
        let mk = |s, e| {
            let mut x = e_(s, e);
            x.action = Action::Anonymize;
            x
        };
        fn e_(s: usize, e: usize) -> Entity {
            Entity::new("PERSON", s, e, "gliner", "r")
        }
        let out = merge_adjacent_same_type(vec![mk(0, 5), mk(6, 13), mk(18, 21)], text);
        assert_eq!(out.len(), 2);
        assert_eq!((out[0].start, out[0].end), (0, 13));
    }
    #[test]
    fn model_inside_secret_is_dropped() {
        let out = merge_entities(
            vec![
                e("API_KEY", 0, 40, "secret", Evidence::Validated, 0.9),
                e("PERSON", 5, 12, "gliner", Evidence::Model, 0.99),
            ],
            &MergeConfig::default(),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].entity_type, "API_KEY");
    }
}
