#!/usr/bin/env python3
"""Render the tables of docs/PERFORMANCE_REPORT.md from build/perf_results.json."""
import json, os
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
R = json.load(open(os.path.join(ROOT, "build/perf_results.json")))


def n(x, d=1):
    if x is None:
        return "–"
    return f"{x:,.{d}f}" if abs(x) < 1000 else f"{x:,.0f}"


titles = {"A": "A. In-process engine, rules only (no HTTP)", "B": "B. detect vs sanitize cost (in-process, 4 threads)", "C": "C. HTTP server, rules only",
          "D": "D. NLP (Presidio recognizers) over HTTP", "E": "E. Hot reload under load and soak"}
for g in "ABCDE":
    rows = [x for x in R["results"] if x.get("group") == g]
    if not rows:
        continue
    print(f"\n### {titles[g]}\n")
    print("| Case | req/s | items/s | mean ms | P50 | P95 | P99 | max | errors | degraded | 503 | CPU % (server) | CPU % (NLP) | RSS MB (server / NLP) |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for x in rows:
        print(f"| {x['name']} | {n(x['qps'])} | {n(x.get('items_per_s'))} | {n(x['mean_ms'],2)} | {n(x['p50_ms'],2)} | {n(x['p95_ms'],2)} | {n(x['p99_ms'],2)} | {n(x.get('max_ms'),1)} | {x['errors']} | {n(x['degraded_responses'],0)} | {x['shed_503']} | {n(x.get('cpu_pct'),0)} | {n(x.get('cpu_pct_nlp'),0)} | {n(x.get('rss_mb'),0)} / {n(x.get('rss_mb_nlp'),0)} |")
rows = [x for x in R["results"] if x.get("group") == "F"]
if rows:
    print("\n### F. Rule compile / hot reload\n")
    print("| Case | wall ms | compile ms | rules |")
    print("|---|---|---|---|")
    for x in rows:
        print(f"| {x['name']} | {n(x['wall_ms'],0)} | {n(x.get('compile_ms'),0)} | {x.get('rules_enabled')} |")
print("\nEnvironment:", json.dumps(R["env"]))
