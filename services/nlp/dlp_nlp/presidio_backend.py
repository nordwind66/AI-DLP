"""Presidio Analyzer wrapper: spaCy NER (en + zh) and Presidio's validated recognizers.

Reused from Presidio (presidio_analyzer 2.2.364): AnalyzerEngine, RecognizerRegistry,
NlpEngineProvider, PhoneRecognizer(phonenumbers), CreditCardRecognizer (Luhn), IbanRecognizer,
CryptoRecognizer, US_* recognizers, SpacyRecognizer. GLiNERRecognizer is deliberately NOT loaded:
GLiNER runs as its own detector so one text is never inferred twice.
"""
import logging, time

from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import PhoneRecognizer

from . import cjk

log = logging.getLogger("dlp_nlp.presidio")

# Presidio entity -> entity vocabulary used by the Rust core
ENTITY_MAP = {
    "PERSON": "PERSON",
    "LOCATION": "LOCATION",
    "ORGANIZATION": "ORGANIZATION",
    "NRP": None,  # nationality / religion / political group: not a PII class we act on
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
PHONE_REGIONS = ("CN", "US", "GB", "HK", "TW", "SG", "JP", "KR", "DE", "FR", "IN", "AU", "CA")


_refine = cjk.refine_entity


class PresidioBackend:
    def __init__(self):
        t0 = time.time()
        conf = {"nlp_engine_name": "spacy", "models": [
            {"lang_code": "en", "model_name": "en_core_web_sm"},
            {"lang_code": "zh", "model_name": "zh_core_web_sm"}]}
        self.nlp = NlpEngineProvider(nlp_configuration=conf).create_engine()
        registry = RecognizerRegistry(supported_languages=["en", "zh"])
        registry.load_predefined_recognizers(languages=["en", "zh"], nlp_engine=self.nlp)
        # default PhoneRecognizer only knows US/UK/DE/...: add CN & friends for BOTH languages
        for lang in ("en", "zh"):
            registry.remove_recognizer("PhoneRecognizer", language=lang)
            registry.add_recognizer(PhoneRecognizer(supported_language=lang, supported_regions=PHONE_REGIONS))
        self.analyzer = AnalyzerEngine(nlp_engine=self.nlp, registry=registry, supported_languages=["en", "zh"])
        self.load_seconds = time.time() - t0
        # warm-up: first call builds lazy structures
        self.analyzer.analyze(text="warm up 张三 John", language="en", entities=["PERSON"])
        self.version = "presidio-analyzer 2.2.364 / spacy en_core_web_sm,zh_core_web_sm 3.8.0"

    def analyze(self, text: str, language: str, entities, threshold: float):
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
                if etype == "PERSON" and r.recognition_metadata and (r.recognition_metadata.get("recognizer_name") == "SpacyRecognizer"):
                    # spaCy small models give a flat 0.85 for every NER hit: it carries no calibration
                    score = min(score, 0.6)
                key = (etype, s, e)
                if key in seen:
                    continue
                seen.add(key)
                rec = (r.recognition_metadata or {}).get("recognizer_name", "")
                out.append({"entity_type": etype, "start": s, "end": e, "score": round(score, 4), "recognizer": rec, "language": lang, "notes": notes})
        return out
