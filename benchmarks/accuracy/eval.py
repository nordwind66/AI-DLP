#!/usr/bin/env python3
"""Accuracy evaluation of Presidio (rule recognizers) / Gitleaks / Unified engine on tests/data/accuracy/dataset.jsonl.

Needs: dlp-server (HTTP, API key in build/run/user.key) and the NLP service running; the upstream
gitleaks difftool (build/bin/gl_difftool, see scripts/gen_gitleaks_expected.sh).

Matching: one-to-one greedy per (case, group). lenient = IoU >= 0.5, strict = identical span.
Predictions of entity groups that are not in the gold label set (LOCATION, IP_PUBLIC, DATE_TIME, ...)
are ignored, never counted as false positives.
"""
import json, os, subprocess, sys, time, urllib.request
from collections import defaultdict

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DATA = os.path.join(ROOT, "tests/data/accuracy/dataset.jsonl")
SERVER = os.environ.get("DLP_URL", "http://127.0.0.1:8080")
NLP = os.environ.get("DLP_NLP", "http://127.0.0.1:8791")
KEY = open(os.path.join(ROOT, "build/run/user.key")).read().strip()

SECRET_T = {"API_KEY", "ACCESS_TOKEN", "REFRESH_TOKEN", "BEARER_TOKEN", "SECRET_KEY", "CLOUD_CREDENTIAL", "LLM_API_KEY", "OAUTH_CREDENTIAL", "JWT_TOKEN", "PRIVATE_KEY", "PASSWORD", "DB_CREDENTIAL", "CLIENT_SECRET"}
GROUP_MAP = {**{t: "SECRET" for t in SECRET_T}, "CREDIT_CARD": "BANK_CARD", "BANK_ACCOUNT": "BANK_CARD", "BANK_CARD": "BANK_CARD",
             "ORGANIZATION_CONFIDENTIAL": "ORGANIZATION", "ORGANIZATION": "ORGANIZATION", "INTERNAL_SYSTEM": "PROJECT_NAME", "PROJECT_NAME": "PROJECT_NAME",
             "PERSON": "PERSON", "PHONE_NUMBER": "PHONE_NUMBER", "EMAIL_ADDRESS": "EMAIL_ADDRESS", "CN_ID_CARD": "CN_ID_CARD", "PASSPORT": "PASSPORT",
             "ADDRESS": "ADDRESS", "DB_CONNECTION_STRING": "DB_CONNECTION_STRING", "IP_INTERNAL": "IP_INTERNAL", "INTERNAL_DOMAIN": "INTERNAL_DOMAIN"}


def post(url, body, key=None, timeout=300):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json", **({"Authorization": f"Bearer {key}"} if key else {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def load():
    return [json.loads(l) for l in open(DATA, encoding="utf-8")]


# ---- systems: each returns list (per case) of [(group, start, end)] ------------------------------------------------
def sys_unified(cases, detectors=None, server=None):
    server = server or SERVER
    out = []
    for i in range(0, len(cases), 16):
        chunk = cases[i:i + 16]
        items = [{"text": c["text"], "policy_id": "audit-only", **({"detectors": detectors} if detectors else {})} for c in chunk]
        res = post(f"{server}/v1/detect/batch", {"items": items}, KEY)["results"]
        for r in res:
            assert r["ok"], r
            out.append([(GROUP_MAP.get(e["entity_type"]), e["start"], e["end"]) for e in r["result"]["entities"] if GROUP_MAP.get(e["entity_type"])])
    return out


def sys_nlp(cases, det):
    out = []
    for i in range(0, len(cases), 8):
        chunk = cases[i:i + 8]
        res = post(f"{NLP}/v1/analyze", {"texts": [c["text"] for c in chunk], "detectors": [det], "language": "auto", "threshold": 0.3}, timeout=900)["results"]
        for r in res:
            out.append([(GROUP_MAP.get(e["entity_type"]), e["start"], e["end"]) for e in r[det] if GROUP_MAP.get(e["entity_type"])])
    return out


def sys_gitleaks_upstream(cases):
    """The real gitleaks (default config, decoding off) run in-process by gl_difftool."""
    p = subprocess.run([os.path.join(ROOT, "build/bin/gl_difftool")], input=json.dumps([c["text"] for c in cases]).encode(), capture_output=True, check=True)
    res = json.loads(p.stdout)
    out = []
    for c, fs in zip(cases, res):
        spans = []
        for f in fs:
            s = c["text"].find(f["secret"])
            if s >= 0:
                spans.append(("SECRET", len(c["text"][:s]), len(c["text"][:s]) + len(f["secret"])))
        out.append(spans)
    return out


# ---- scoring ----------------------------------------------------------------------------------------------------------
def iou(a, b):
    inter = max(0, min(a[1], b[1]) - max(a[0], b[0]))
    union = (a[1] - a[0]) + (b[1] - b[0]) - inter
    return inter / union if union else 0.0


def score(cases, preds, groups, restrict=None):
    """returns per-group counts for strict and lenient matching"""
    stats = {m: defaultdict(lambda: [0, 0, 0]) for m in ("strict", "lenient")}  # tp, fp, fn
    for c, pr in zip(cases, preds):
        gold = [(e["type"], e["start"], e["end"]) for e in c["entities"] if e["type"] in groups]
        pred = [p for p in pr if p[0] in groups]
        for mode in ("strict", "lenient"):
            used = set()
            for g in gold:
                best, bj = 0.0, None
                for j, p in enumerate(pred):
                    if j in used or p[0] != g[0]:
                        continue
                    v = 1.0 if (p[1], p[2]) == (g[1], g[2]) else (iou((g[1], g[2]), (p[1], p[2])) if mode == "lenient" else 0.0)
                    if v > best:
                        best, bj = v, j
                ok = best >= (1.0 if mode == "strict" else 0.5)
                if ok:
                    used.add(bj)
                    stats[mode][g[0]][0] += 1
                else:
                    stats[mode][g[0]][2] += 1
            for j, p in enumerate(pred):
                if j not in used:
                    stats[mode][p[0]][1] += 1
    return stats


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def negatives_fpr(cases, preds, groups):
    neg = [(c, p) for c, p in zip(cases, preds) if not c["entities"]]
    hit = sum(1 for c, p in neg if any(x[0] in groups for x in p))
    return hit, len(neg)


def main():
    cases = load()
    gold_groups = sorted({e["type"] for c in cases for e in c["entities"]})
    systems = {}
    runs = [
        ("unified (all detectors)", lambda: sys_unified(cases), None),
        ("unified rules-only (regex+secret+dictionary)", lambda: sys_unified(cases, ["regex", "secret", "dictionary"]), None),
        ("presidio alone", lambda: sys_nlp(cases, "presidio"), None),
        ("gitleaks upstream (real binary)", lambda: sys_gitleaks_upstream(cases), {"SECRET"}),
        ("gitleaks rules only, run by this engine", lambda: sys_unified(cases, ["secret"], server=os.environ.get("DLP_URL_GL", "http://127.0.0.1:8081")), {"SECRET"}),
    ]
    results = {"dataset": {"cases": len(cases), "gold_entities": sum(len(c["entities"]) for c in cases), "negatives": sum(1 for c in cases if not c["entities"])}, "systems": {}}
    for name, fn, only in runs:
        t0 = time.time()
        preds = fn()
        el = time.time() - t0
        groups = only or set(gold_groups)
        st = score(cases, preds, groups)
        entry = {"seconds": round(el, 2), "ms_per_case": round(el * 1000 / len(cases), 2), "per_type": {}, "groups": sorted(groups)}
        for mode in ("strict", "lenient"):
            tot = [0, 0, 0]
            for g in sorted(groups):
                tp, fp, fn_ = st[mode][g]
                p, r, f = prf(tp, fp, fn_)
                entry["per_type"].setdefault(g, {})[mode] = {"tp": tp, "fp": fp, "fn": fn_, "precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}
                tot = [tot[0] + tp, tot[1] + fp, tot[2] + fn_]
            p, r, f = prf(*tot)
            entry[f"micro_{mode}"] = {"tp": tot[0], "fp": tot[1], "fn": tot[2], "precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4), "false_negative_rate": round(1 - r, 4)}
        hit, n = negatives_fpr(cases, preds, groups)
        entry["negative_text_fpr"] = {"texts_with_false_alarm": hit, "negative_texts": n, "fpr": round(hit / n, 4)}
        # category-level FPR on explicitly hard negatives
        cat = defaultdict(lambda: [0, 0])
        for c, p in zip(cases, preds):
            if not c["entities"]:
                cat[c["category"]][1] += 1
                cat[c["category"]][0] += int(any(x[0] in groups for x in p))
        entry["negative_fpr_by_category"] = {k: {"false_alarm": v[0], "n": v[1]} for k, v in sorted(cat.items())}
        # high-risk credentials: miss vs false alarm
        if "SECRET" in groups:
            tp, fp, fn_ = st["lenient"]["SECRET"]
            entry["credentials"] = {"recall": round(tp / (tp + fn_), 4) if tp + fn_ else None, "missed": fn_, "gold": tp + fn_, "false_alarms": fp}
        results["systems"][name] = entry
        print(f"{name:52s} microF1(lenient)={entry['micro_lenient']['f1']:.3f} P={entry['micro_lenient']['precision']:.3f} R={entry['micro_lenient']['recall']:.3f}  negFPR={entry['negative_text_fpr']['fpr']:.3f}  {entry['ms_per_case']} ms/case", flush=True)
        results.setdefault("_preds", {})[name] = preds
    # persist errors for analysis (offsets only, never values beyond the synthetic text)
    out = os.path.join(ROOT, "build/accuracy_results.json")
    preds = results.pop("_preds")
    json.dump(results, open(out, "w"), ensure_ascii=False, indent=1)
    json.dump({k: v for k, v in preds.items()}, open(os.path.join(ROOT, "build/accuracy_preds.json"), "w"))
    print("wrote", out)


if __name__ == "__main__":
    main()
