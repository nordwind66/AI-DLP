import os
from dataclasses import dataclass


@dataclass
class Settings:
    presidio_enabled: bool = os.environ.get("DLP_PRESIDIO", "1") != "0"
    # concurrent analyses allowed inside the process and how many may wait (back-pressure)
    max_concurrency: int = int(os.environ.get("DLP_NLP_CONCURRENCY", "2"))
    max_queue: int = int(os.environ.get("DLP_NLP_QUEUE", "32"))
    max_text_chars: int = int(os.environ.get("DLP_NLP_MAX_CHARS", "1000000"))
    # shared secret between the Rust core and this service (loopback only); empty = none
    auth_token: str = os.environ.get("DLP_NLP_TOKEN", "")
