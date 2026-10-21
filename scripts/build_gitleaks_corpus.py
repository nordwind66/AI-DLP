"""Turn build/corpus_raw.jsonl (dumped by the patched generator) into tests/data/gitleaks_corpus.json."""
import json, sys, os
root = sys.argv[1]
samples, meta, seen = [], [], set()
for line in open(os.path.join(root, "build/corpus_raw.jsonl")):
    d = json.loads(line)
    for kind in ("tps", "fps"):
        for s in d[kind] or []:
            if s in seen:
                continue
            seen.add(s)
            samples.append(s)
            meta.append({"rule": d["rule"], "kind": kind[:-1]})
json.dump({"samples": samples, "meta": meta}, open(os.path.join(root, "tests/data/gitleaks_corpus.json"), "w"), ensure_ascii=False)
json.dump(samples, open(os.path.join(root, "build/samples.json"), "w"))
print(len(samples), "unique samples")
