import json, os
from dataclasses import dataclass, field

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

# GLiNER label (English prompt text works best, see docs/M1 findings) -> (entity_type, min_score)
DEFAULT_GLINER_LABELS = {
    "person": ("PERSON", 0.5),
    "email": ("EMAIL_ADDRESS", 0.6),
    "phone number": ("PHONE_NUMBER", 0.6),
    "address": ("ADDRESS", 0.5),
    "organization": ("ORGANIZATION", 0.5),
    "credit card number": ("CREDIT_CARD", 0.6),
    "passport number": ("PASSPORT", 0.6),
    "bank account number": ("BANK_ACCOUNT", 0.6),
    "social security number": ("NATIONAL_ID", 0.6),
    "id card number": ("NATIONAL_ID", 0.6),
    "date of birth": ("DATE_OF_BIRTH", 0.6),
}


@dataclass
class Settings:
    models_dir: str = os.environ.get("DLP_MODELS_DIR", os.path.join(ROOT, "models"))
    gliner_model: str = os.environ.get("DLP_GLINER_MODEL", "gliner_multi_pii-v1")
    gliner_enabled: bool = os.environ.get("DLP_GLINER", "1") != "0"
    presidio_enabled: bool = os.environ.get("DLP_PRESIDIO", "1") != "0"
    gliner_onnx: bool = os.environ.get("DLP_GLINER_ONNX", "0") == "1"
    gliner_cjk_split: bool = os.environ.get("DLP_GLINER_CJK_SPLIT", "1") != "0"
    torch_threads: int = int(os.environ.get("DLP_TORCH_THREADS", "4"))
    # concurrent inferences allowed inside the process and how many may wait (back-pressure)
    max_concurrency: int = int(os.environ.get("DLP_NLP_CONCURRENCY", "2"))
    max_queue: int = int(os.environ.get("DLP_NLP_QUEUE", "32"))
    max_text_chars: int = int(os.environ.get("DLP_NLP_MAX_CHARS", "1000000"))
    chunk_chars: int = int(os.environ.get("DLP_GLINER_CHUNK", "300"))
    chunk_overlap: int = int(os.environ.get("DLP_GLINER_OVERLAP", "60"))
    gliner_batch: int = int(os.environ.get("DLP_GLINER_BATCH", "8"))
    labels: dict = field(default_factory=lambda: dict(DEFAULT_GLINER_LABELS))
    # shared secret between the Rust core and this service (loopback only); empty = none
    auth_token: str = os.environ.get("DLP_NLP_TOKEN", "")

    def __post_init__(self):
        p = os.environ.get("DLP_GLINER_LABELS")
        if p and os.path.exists(p):
            raw = json.load(open(p, encoding="utf-8"))
            self.labels = {k: (v[0], float(v[1])) for k, v in raw.items()}
