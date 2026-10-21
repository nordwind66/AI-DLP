"""Presidio Analyzer wrapper: Presidio's deterministic recognizers only (no statistical model).

Reused from Presidio (presidio_analyzer 2.2.364): AnalyzerEngine, RecognizerRegistry, NlpEngineProvider,
PhoneRecognizer (libphonenumber), CreditCardRecognizer (Luhn), IbanRecognizer, CryptoRecognizer, EmailRecognizer,
US_* recognizers. Presidio needs a tokenizing NLP engine; we give it a *blank* spaCy pipeline (tokenizer rules
only, no trained weights, no NER, nothing downloaded). Presidio's SpacyRecognizer (the NER wrapper) is removed, so
PERSON / LOCATION / ORGANIZATION are never produced here: names are found by the Rust rules (labelled names,
possessives, dictionaries) only.
"""
import logging, os, tempfile, time

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import PhoneRecognizer

from . import cjk

log = logging.getLogger("dlp_nlp.presidio")

# Presidio entity -> entity vocabulary used by the Rust core
ENTITY_MAP = {
    "PHONE_NUMBER": "PHONE_NUMBER",
    "EMAIL_ADDRESS": "EMAIL_ADDRESS",
    "CREDIT_CARD": "CREDIT_CARD",
    "IBAN_CODE": "IBAN",
    "CRYPTO": "CRYPTO_WALLET",
    "US_SSN": "NATIONAL_ID",
    "US_PASSPORT": "PASSPORT",
    "US_DRIVER_LICENSE": "DRIVER_LICENSE",
    "US_ITIN": "NATIONAL_ID",
    "US_BANK_NUMBER": "BANK_ACCOUNT",
    "UK_NHS": "NATIONAL_ID",
    "MEDICAL_LICENSE": "MEDICAL_LICENSE",
}
DEFAULT_ENTITIES = list(k for k, v in ENTITY_MAP.items() if v)
CHUNK = 8000
OVERLAP = 64
PHONE_REGIONS = ("CN", "US", "GB", "HK", "TW", "SG", "JP", "KR", "DE", "FR", "IN", "AU", "CA")


_refine = cjk.refine_entity


def _blank_models():
    """Create tokenizer-only spaCy pipelines on disk (Presidio loads its NLP model by name/path)."""
    import spacy
    root = os.path.join(os.environ.get("DLP_MODELS_DIR", tempfile.gettempdir()), "spacy_blank")
    paths = {}
    for lang in ("en", "zh"):
        p = os.path.join(root, lang)
        if not os.path.exists(os.path.join(p, "meta.json")):
            os.makedirs(p, exist_ok=True)
            spacy.blank(lang).to_disk(p)
        paths[lang] = p
    return paths


class PresidioBackend:
    def __init__(self):
        t0 = time.time()
        blank = _blank_models()
        conf = {"nlp_engine_name": "spacy", "models": [
            {"lang_code": "en", "model_name": blank["en"]},
            {"lang_code": "zh", "model_name": blank["zh"]}]}
        self.nlp = NlpEngineProvider(nlp_configuration=conf).create_engine()
        registry = RecognizerRegistry(supported_languages=["en", "zh"])
        registry.load_predefined_recognizers(languages=["en", "zh"], nlp_engine=self.nlp)
        for lang in ("en", "zh"):
            for rec in list(registry.recognizers):
                if rec.name == "SpacyRecognizer" and rec.supported_language == lang:
                    registry.remove_recognizer("SpacyRecognizer", language=lang)
        # default PhoneRecognizer only knows US/UK/DE/...: add CN & friends for BOTH languages
        for lang in ("en", "zh"):
            registry.remove_recognizer("PhoneRecognizer", language=lang)
            registry.add_recognizer(PhoneRecognizer(supported_language=lang, supported_regions=PHONE_REGIONS))
        self.analyzer = AnalyzerEngine(nlp_engine=self.nlp, registry=registry, supported_languages=["en", "zh"])
        self.load_seconds = time.time() - t0
        # warm-up: first call builds lazy structures
        self.analyzer.analyze(text="warm up 13800138000 a@b.com", language="en", entities=["PHONE_NUMBER", "EMAIL_ADDRESS"])
        self.version = "presidio-analyzer 2.2.364 (rule recognizers only; blank spaCy tokenizer, no NER model)"

    def analyze(self, text: str, language: str, entities, threshold: float, budget_s: float = 25.0):
        """Analyze ``text`` in bounded chunks. Presidio's cost is superlinear in text length (measured: 10 KB 0.25 s,
        100 KB 7.5 s), so long texts are cut at whitespace into ~CHUNK characters with a small overlap; hits that
        straddle a cut are found in the overlap and de-duplicated. ``budget_s`` bounds the work so a giant request
        cannot occupy a slot after the caller has given up (TimeoutError -> detector error -> degraded/fail-closed)."""
        if len(text) <= CHUNK:
            return self._analyze_one(text, 0, language, entities, threshold)
        deadline = time.monotonic() + budget_s
        out, seen, pos = [], set(), 0
        while pos < len(text):
            if time.monotonic() > deadline:
                raise TimeoutError("presidio budget exceeded")
            end = min(len(text), pos + CHUNK)
            if end < len(text):
                cut = max(text.rfind(c, pos + CHUNK // 2, end) for c in (" ", "\n", "\t"))
                if cut > pos:
                    end = cut + 1
            for d in self._analyze_one(text[pos:end], pos, language, entities, threshold):
                k = (d["entity_type"], d["start"], d["end"])
                if k not in seen:
                    seen.add(k)
                    out.append(d)
            if end >= len(text):
                break
            pos = max(end - OVERLAP, pos + 1)
        return out

    def _analyze_one(self, text: str, base: int, language: str, entities, threshold: float):
        langs = cjk.detect_langs(text) if language in ("auto", "", None) else [language if language in ("en", "zh") else "en"]
        wanted = [e for e in (entities or DEFAULT_ENTITIES) if e in ENTITY_MAP or e in ENTITY_MAP.values()]
        presidio_entities = [k for k, v in ENTITY_MAP.items() if v and (k in wanted or v in wanted)]
        out, seen = [], set()
        for lang in langs:
            ents = [e for e in presidio_entities if e in self.analyzer.get_supported_entities(lang)]
            if not ents:
                continue
            for r in self.analyzer.analyze(text=text, language=lang, entities=ents, score_threshold=threshold):
                etype = ENTITY_MAP.get(r.entity_type)
                if not etype:
                    continue
                s, e, score, notes = r.start, r.end, float(r.score), {}
                ref = _refine(etype, text, s, e, score)
                if ref is None:
                    continue
                s, e, score, notes = ref
                s, e = s + base, e + base
                key = (etype, s, e)
                if key in seen:
                    continue
                seen.add(key)
                rec = (r.recognition_metadata or {}).get("recognizer_name", "")
                out.append({"entity_type": etype, "start": s, "end": e, "score": round(score, 4), "recognizer": rec, "language": lang, "notes": notes})
        return out
