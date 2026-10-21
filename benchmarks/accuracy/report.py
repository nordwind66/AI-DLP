#!/usr/bin/env python3
"""Render the tables of docs/ACCURACY_REPORT.md from build/accuracy_results.json + accuracy_preds.json."""
import json, os, sys
from collections import defaultdict
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
R = json.load(open(os.path.join(ROOT, "build/accuracy_results.json")))
P = json.load(open(os.path.join(ROOT, "build/accuracy_preds.json")))
CASES = [json.loads(l) for l in open(os.path.join(ROOT, "tests/data/accuracy/dataset.jsonl"), encoding="utf-8")]


def f(x):
    return f"{x:.3f}"


print("### Overall (micro-average over the entity groups each system can report)\n")
print("| System | P (lenient) | R (lenient) | F1 (lenient) | F1 (strict) | FNR | text-level FPR | ms/case |")
print("|---|---|---|---|---|---|---|---|")
for n, s in R["systems"].items():
    l, st = s["micro_lenient"], s["micro_strict"]
    print(f"| {n} | {f(l['precision'])} | {f(l['recall'])} | {f(l['f1'])} | {f(st['f1'])} | {f(l['false_negative_rate'])} | {f(s['negative_text_fpr']['fpr'])} ({s['negative_text_fpr']['texts_with_false_alarm']}/{s['negative_text_fpr']['negative_texts']}) | {s['ms_per_case']} |")

for n in ("unified (all detectors)", "presidio alone"):
    s = R["systems"][n]
    print(f"\n### Per entity type: {n}\n")
    print("| Type | TP | FP | FN | P | R | F1 | strict F1 |")
    print("|---|---|---|---|---|---|---|---|")
    for t, v in s["per_type"].items():
        l = v["lenient"]
        print(f"| {t} | {l['tp']} | {l['fp']} | {l['fn']} | {f(l['precision'])} | {f(l['recall'])} | {f(l['f1'])} | {f(v['strict']['f1'])} |")

# PERSON by language, unified
preds = P["unified (all detectors)"]
print("\n### PERSON / ORGANIZATION recall by language (unified, lenient IoU>=0.5)\n")
print("| Type | lang | gold | found | recall |")
print("|---|---|---|---|---|")
for typ in ("PERSON", "ORGANIZATION"):
    for lang in sorted({c["lang"] for c in CASES}):
        gold = found = 0
        for c, p in zip(CASES, preds):
            if c["lang"] != lang:
                continue
            for g in c["entities"]:
                if g["type"] != typ:
                    continue
                gold += 1
                for (t, s, e) in p:
                    if t == typ:
                        inter = max(0, min(e, g["end"]) - max(s, g["start"]))
                        union = max(e, g["end"]) - min(s, g["start"])
                        if union and inter / union >= 0.5:
                            found += 1
                            break
        if gold:
            print(f"| {typ} | {lang} | {gold} | {found} | {f(found / gold)} |")

print("\n### False alarms on the 179 negative texts, by category (unified)\n")
print("| Category | texts | false alarms |")
print("|---|---|---|")
for k, v in R["systems"]["unified (all detectors)"]["negative_fpr_by_category"].items():
    print(f"| {k} | {v['n']} | {v['false_alarm']} |")

print("\n### Credentials (SECRET group, lenient)\n")
print("| System | gold | missed | recall | false alarms |")
print("|---|---|---|---|---|")
for n, s in R["systems"].items():
    c = s.get("credentials")
    if c:
        print(f"| {n} | {c['gold']} | {c['missed']} | {c['recall']} | {c['false_alarms']} |")
