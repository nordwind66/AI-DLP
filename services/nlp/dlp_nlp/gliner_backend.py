"""GLiNER wrapper (CPU). One model instance per process; offline; long-text chunking with char offsets.

Reused from GLiNER (gliner 0.2.29): GLiNER.from_pretrained, predict_entities / batch_predict_entities
(span scoring, flat NER, threshold). Added here: chunking on sentence boundaries with overlap,
code-point offset bookkeeping, label->entity mapping, de-duplication across chunks and CJK person
boundary refinement.
"""
import logging, os, re, threading, time

from . import cjk

log = logging.getLogger("dlp_nlp.gliner")
_SENT_END = re.compile(r"[。！？!?；;\n]")


def chunk_text(text: str, size: int, overlap: int):
    """Yield (offset, chunk). Prefers cutting after sentence-ending punctuation."""
    n = len(text)
    if n <= size:
        yield 0, text
        return
    pos = 0
    while pos < n:
        end = min(n, pos + size)
        if end < n:
            window = text[max(pos, end - 120):end]
            ms = list(_SENT_END.finditer(window))
            if ms:
                end = max(pos, end - 120) + ms[-1].end()
        yield pos, text[pos:end]
        if end >= n:
            break
        pos = max(end - overlap, pos + 1)


class GlinerBackend:
    def __init__(self, settings):
        import torch
        from gliner import GLiNER

        self.s = settings
        torch.set_num_threads(settings.torch_threads)
        path = os.path.join(settings.models_dir, settings.gliner_model)
        t0 = time.time()
        kw = {"local_files_only": True}
        if settings.gliner_onnx:
            kw.update(load_onnx_model=True, onnx_model_file="model.onnx")
        self.model = GLiNER.from_pretrained(path, **kw)
        self.model.eval()
        if settings.gliner_cjk_split:
            # default GLiNER treats a run of Han characters as ONE word (see splitter.py); measured effect:
            # Chinese PERSON recall 0.48 -> 0.99 (docs/ACCURACY_REPORT.md)
            from .splitter import install
            install(self.model)
        self.load_seconds = time.time() - t0
        self.labels = list(settings.labels.keys())
        self._lock = threading.Lock()
        self.model.predict_entities("warm up John Smith", self.labels, threshold=0.5)
        rss = _rss_mb()
        self.rss_mb = rss
        self.version = f"gliner 0.2.29 / {settings.gliner_model}{' (onnx)' if settings.gliner_onnx else ''}"

    def _map(self, text, offset, ents, wanted, out):
        for e in ents:
            et, thr = self.s.labels.get(e["label"], (None, 1.0))
            if not et or (wanted and et not in wanted) or e["score"] < thr:
                continue
            s, en, score, notes = offset + e["start"], offset + e["end"], float(e["score"]), {}
            ref = cjk.refine_entity(et, text, s, en, score)
            if ref is None:
                continue
            s, en, score, notes = ref
            out.append({"entity_type": et, "start": s, "end": en, "score": round(score, 4), "recognizer": "gliner", "label": e["label"], "notes": notes})

    def analyze_many(self, texts, entities, threshold):
        """texts: list[str]. Returns list[list[dict]] aligned with texts."""
        import torch

        wanted = set(entities or [])
        labels = [l for l in self.labels if not wanted or self.s.labels[l][0] in wanted]
        results = [[] for _ in texts]
        if not labels:
            return results
        work = []  # (text_idx, offset, chunk)
        for i, t in enumerate(texts):
            if not t.strip():
                continue
            for off, ch in chunk_text(t, self.s.chunk_chars, self.s.chunk_overlap):
                work.append((i, off, ch))
        thr = max(0.05, min(threshold, 0.95))
        with torch.inference_mode():
            for b in range(0, len(work), self.s.gliner_batch):
                batch = work[b:b + self.s.gliner_batch]
                preds = self.model.batch_predict_entities([w[2] for w in batch], labels, threshold=thr, flat_ner=True)
                for (i, off, ch), ents in zip(batch, preds):
                    self._map(texts[i], off, ents, wanted, results[i])
        for i in range(len(results)):
            results[i] = _dedupe(results[i])
        return results


def _dedupe(items):
    """Chunk overlap produces duplicates: keep the best-scoring span per (type, overlapping range)."""
    items.sort(key=lambda d: (d["entity_type"], d["start"], -d["score"]))
    out = []
    for d in items:
        if out and out[-1]["entity_type"] == d["entity_type"] and d["start"] < out[-1]["end"]:
            if d["score"] > out[-1]["score"] and d["end"] - d["start"] >= out[-1]["end"] - out[-1]["start"]:
                out[-1] = d
            elif d["end"] > out[-1]["end"] and d["score"] >= out[-1]["score"] - 0.05:
                out[-1]["end"] = d["end"]
            continue
        out.append(d)
    return sorted(out, key=lambda d: d["start"])


def _rss_mb():
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024
    except OSError:
        pass
    try:
        import psutil
        return psutil.Process().memory_info().rss / 1048576
    except Exception:
        return -1
