"""HTTP service exposing Presidio and GLiNER to the Rust core over loopback.

Models load once at startup and stay resident. A bounded in-process queue provides back-pressure:
when more than ``max_queue`` requests wait for a free inference slot the service answers 503
instead of building unbounded latency. Offsets are Unicode code points; the Rust side converts.
"""
import logging, os, sys, threading, time

os.environ.setdefault("HF_HOME", os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")), "models", "hf_home"))
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from . import __version__
from .config import Settings

log = logging.getLogger("dlp_nlp")
S = Settings()
state = {"presidio": None, "gliner": None, "errors": {}, "started": time.time()}
_slots = threading.BoundedSemaphore(S.max_concurrency)
_waiting = 0
_wlock = threading.Lock()
_metrics = {"requests": 0, "rejected": 0, "errors": 0, "presidio_ms": 0.0, "gliner_ms": 0.0}


def load_models():
    if S.presidio_enabled:
        try:
            from .presidio_backend import PresidioBackend
            state["presidio"] = PresidioBackend()
            log.info("presidio ready in %.1fs", state["presidio"].load_seconds)
        except Exception as e:  # keep serving the other backend; status reports the failure
            state["errors"]["presidio"] = f"{type(e).__name__}: {e}"
            log.exception("presidio failed to load")
    if S.gliner_enabled:
        try:
            from .gliner_backend import GlinerBackend
            state["gliner"] = GlinerBackend(S)
            log.info("gliner ready in %.1fs", state["gliner"].load_seconds)
        except Exception as e:
            state["errors"]["gliner"] = f"{type(e).__name__}: {e}"
            log.exception("gliner failed to load")


app = FastAPI(title="ai-dlp-nlp", version=__version__)


@app.on_event("startup")
def _startup():
    load_models()


class AnalyzeRequest(BaseModel):
    texts: list[str] = Field(..., max_length=256)
    detectors: list[str] = ["presidio", "gliner"]
    language: str = "auto"
    entities: list[str] = []
    threshold: float = 0.3
    request_id: str = ""


def _check(token):
    if S.auth_token and token != S.auth_token:
        raise HTTPException(status_code=401, detail="bad token")


@app.get("/health")
def health():
    return {"status": "ok" if (state["presidio"] or not S.presidio_enabled) and (state["gliner"] or not S.gliner_enabled) else "degraded"}


@app.get("/status")
def status(x_dlp_token: str = Header(default="")):
    _check(x_dlp_token)
    def one(name, backend, enabled):
        if not enabled:
            return {"state": "disabled", "message": "disabled by configuration"}
        if backend is None:
            return {"state": "unavailable", "message": state["errors"].get(name, "not loaded")}
        return {"state": "ready", "message": "", "version": backend.version, "load_seconds": round(backend.load_seconds, 2)}
    return {
        "version": __version__,
        "uptime_s": round(time.time() - state["started"], 1),
        "presidio": one("presidio", state["presidio"], S.presidio_enabled),
        "gliner": one("gliner", state["gliner"], S.gliner_enabled),
        "concurrency": S.max_concurrency,
        "queue_limit": S.max_queue,
        "metrics": _metrics,
        "rss_mb": round(__import__("dlp_nlp.gliner_backend", fromlist=["_rss_mb"])._rss_mb(), 1),
    }


@app.post("/v1/analyze")
def analyze(req: AnalyzeRequest, x_dlp_token: str = Header(default="")):
    global _waiting
    _check(x_dlp_token)
    total = sum(len(t) for t in req.texts)
    if any(len(t) > S.max_text_chars for t in req.texts):
        raise HTTPException(status_code=413, detail="text too large")
    with _wlock:
        if _waiting >= S.max_queue:
            _metrics["rejected"] += 1
            raise HTTPException(status_code=503, detail="overloaded")
        _waiting += 1
    try:
        _slots.acquire()
    finally:
        with _wlock:
            _waiting -= 1
    try:
        _metrics["requests"] += 1
        n = len(req.texts)
        out = {"results": [{"presidio": [], "gliner": []} for _ in range(n)], "detectors": {}}
        for det in req.detectors:
            backend = state.get(det)
            if backend is None:
                out["detectors"][det] = {"state": "unavailable", "message": state["errors"].get(det, "not loaded or disabled")}
                continue
            t0 = time.perf_counter()
            try:
                if det == "presidio":
                    for i, t in enumerate(req.texts):
                        out["results"][i]["presidio"] = backend.analyze(t, req.language, req.entities, req.threshold) if t.strip() else []
                else:
                    res = backend.analyze_many(req.texts, req.entities, req.threshold)
                    for i, r in enumerate(res):
                        out["results"][i]["gliner"] = r
                ms = (time.perf_counter() - t0) * 1000
                _metrics[f"{det}_ms"] += ms
                out["detectors"][det] = {"state": "ready", "ms": round(ms, 2)}
            except Exception as e:
                _metrics["errors"] += 1
                log.exception("%s failed", det)
                out["detectors"][det] = {"state": "error", "message": f"{type(e).__name__}"}  # never echo text
        return out
    finally:
        _slots.release()


def main():
    import uvicorn
    logging.basicConfig(level=os.environ.get("DLP_LOG", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    host = os.environ.get("DLP_NLP_HOST", "127.0.0.1")
    port = int(os.environ.get("DLP_NLP_PORT", "8791"))
    uvicorn.run(app, host=host, port=port, log_level="warning", workers=1, timeout_keep_alive=30)


if __name__ == "__main__":
    main()
