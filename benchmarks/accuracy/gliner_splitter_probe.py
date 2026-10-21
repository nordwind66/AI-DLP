"""Does a CJK-aware word splitter fix GLiNER's Chinese span problem?  default vs char-level Han tokens."""
import json, os, sys
os.environ.setdefault("HF_HOME", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "models", "hf_home"))
os.environ.setdefault("HF_HUB_OFFLINE", "1")
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "services", "nlp"))
import torch; torch.set_num_threads(2)
from gliner import GLiNER
from dlp_nlp import cjk
from dlp_nlp.splitter import install
cases = [json.loads(l) for l in open(os.path.join(ROOT, "tests/data/accuracy/dataset.jsonl"), encoding="utf-8")]
sub = [c for c in cases if c["lang"] in ("zh", "mixed") and c["category"] in ("pii_zh", "mixed", "org", "multi", "chat", "three_han", "confusable")][:260]

def run(model, labels, thr, refine, target, etype_map):
    tp = fp = fn = 0
    for c in sub:
        preds = []
        for e in model.predict_entities(c["text"], labels, threshold=thr, flat_ner=True):
            t = etype_map.get(e["label"])
            if t != target: continue
            s, en, sc = e["start"], e["end"], e["score"]
            if refine:
                r = cjk.refine_entity(target, c["text"], s, en, sc)
                if r is None: continue
                s, en = r[0], r[1]
            preds.append((s, en))
        gold = [(g["start"], g["end"]) for g in c["entities"] if g["type"] == target]
        used = set()
        for g in gold:
            j = next((j for j, p in enumerate(preds) if j not in used and p[0] < g[1] and g[0] < p[1]), None)
            if j is None: fn += 1
            else: used.add(j); tp += 1
        fp += len(preds) - len(used)
    p = tp / (tp + fp) if tp + fp else 0; r = tp / (tp + fn) if tp + fn else 0
    return p, r, (2 * p * r / (p + r) if p + r else 0), tp, fp, fn

LABELS = ["person", "organization", "address", "email", "phone number"]
MAP = {"person": "PERSON", "organization": "ORGANIZATION", "address": "ADDRESS", "email": "EMAIL_ADDRESS", "phone number": "PHONE_NUMBER"}
out = {}
for name in sys.argv[1:] or ["gliner_multi_pii-v1"]:
    m = GLiNER.from_pretrained(os.path.join(ROOT, "models", name), local_files_only=True)
    for variant in ("default", "cjk-char"):
        if variant == "cjk-char": install(m)
        for target in ("PERSON", "ORGANIZATION", "ADDRESS"):
            for thr in (0.3, 0.5):
                for refine in (False, True):
                    p, r, f, tp, fp, fn = run(m, LABELS, thr, refine, target, MAP)
                    out[f"{name}|{variant}|{target}|thr{thr}|refine{int(refine)}"] = dict(p=p, r=r, f1=f, tp=tp, fp=fp, fn=fn)
                    print(f"{name:20s} {variant:9s} {target:12s} thr={thr} refine={int(refine)}  P={p:.2f} R={r:.2f} F1={f:.2f}  tp={tp} fp={fp} fn={fn}", flush=True)
json.dump(out, open(os.path.join(ROOT, "build/gliner_splitter_probe.json"), "w"), indent=1)
