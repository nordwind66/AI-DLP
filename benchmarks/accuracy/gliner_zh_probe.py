"""Label / threshold / segmentation probe for Chinese person+organization recall (offline, CPU).
Run:  python benchmarks/accuracy/gliner_zh_probe.py   (uses the venv with gliner installed)"""
import json, os, re, sys, time, itertools
os.environ.setdefault("HF_HOME", os.path.join(os.path.dirname(__file__), "..", "..", "models", "hf_home"))
os.environ.setdefault("HF_HUB_OFFLINE", "1")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "services", "nlp"))
import torch
torch.set_num_threads(4)
from gliner import GLiNER
from dlp_nlp import cjk

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
cases = [json.loads(l) for l in open(os.path.join(ROOT, "tests/data/accuracy/dataset.jsonl"), encoding="utf-8")]
sub = [c for c in cases if c["lang"] in ("zh", "mixed") and c["category"] in ("pii_zh", "mixed", "org", "multi", "chat", "three_han", "confusable")][:260]
print(len(sub), "zh/mixed cases", sum(len([e for e in c["entities"] if e["type"] == "PERSON"]) for c in sub), "gold persons")

CLAUSE = re.compile(r"[^，。；;！？!?\n]+")
def clauses(text):
    return [(m.start(), m.group()) for m in CLAUSE.finditer(text)]

def run(model, labels, thr, segment, refine, target="PERSON"):
    tp = fp = fn = 0
    for c in sub:
        preds = []
        pieces = clauses(c["text"]) if segment else [(0, c["text"])]
        for off, t in pieces:
            if not t.strip(): continue
            for e in model.predict_entities(t, labels, threshold=thr, flat_ner=True):
                s, en, sc = off + e["start"], off + e["end"], e["score"]
                if refine:
                    r = cjk.refine_entity(target, c["text"], s, en, sc)
                    if r is None: continue
                    s, en, sc = r[0], r[1], r[2]
                preds.append((s, en))
        gold = [(e["start"], e["end"]) for e in c["entities"] if e["type"] == target]
        used = set()
        for g in gold:
            j = next((j for j, p in enumerate(preds) if j not in used and p[0] < g[1] and g[0] < p[1]), None)
            if j is None: fn += 1
            else: used.add(j); tp += 1
        fp += len(preds) - len(used)
    p = tp / (tp + fp) if tp + fp else 0; r = tp / (tp + fn) if tp + fn else 0
    return p, r, 2 * p * r / (p + r) if p + r else 0

root = os.path.join(ROOT, "models")
rows = []
for name in ["gliner_multi_pii-v1", "gliner_multi-v2.1"]:
    model = GLiNER.from_pretrained(os.path.join(root, name), local_files_only=True)
    for labels in (["person"], ["person name"], ["name"], ["人名"], ["person", "人名"], ["full name of a person"], ["姓名"], ["Chinese person name"]):
        for thr in (0.3, 0.5):
            for segment in (False, True):
                t0 = time.time()
                p, r, f = run(model, labels, thr, segment, refine=True)
                rows.append((f, name, labels, thr, segment, p, r, time.time() - t0))
                print(f"{name:20s} {str(labels):34s} thr={thr} seg={int(segment)}  P={p:.2f} R={r:.2f} F1={f:.2f}  ({time.time()-t0:.0f}s)", flush=True)
rows.sort(reverse=True)
print("\nTOP 6 by F1 (person, with CJK refinement):")
for f, n, l, t, s, p, r, _ in rows[:6]:
    print(f"  F1={f:.3f} P={p:.2f} R={r:.2f}  {n} labels={l} thr={t} segment={s}")
json.dump([dict(f1=f, model=n, labels=l, thr=t, segment=s, p=p, r=r) for f, n, l, t, s, p, r, _ in rows], open(os.path.join(ROOT, "build/gliner_zh_probe.json"), "w"), ensure_ascii=False, indent=1)
