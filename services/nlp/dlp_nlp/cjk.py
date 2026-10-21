"""Language heuristic and structural post-filters for Presidio's pattern recognizers.

The service runs NO statistical model (no NER). Presidio's recognizers are regular expressions plus
checksums / libphonenumber; they are deliberately permissive, so hits that are structurally wrong
(timestamps accepted as phone numbers, e-mail look-alikes) are dropped here. Offsets are code points.
"""
import re

_HAN = re.compile(r"[\u4e00-\u9fff]")


def han_ratio(text: str) -> float:
    if not text:
        return 0.0
    return len(_HAN.findall(text)) / max(1, len(text))


def detect_langs(text: str):
    """Language codes (Presidio recognizer sets) to run for this text."""
    letters = sum(1 for c in text if c.isalpha())
    han = len(_HAN.findall(text))
    latin = sum(1 for c in text if c.isascii() and c.isalpha())
    langs = []
    if han >= 2 and han / max(1, letters) >= 0.1:
        langs.append("zh")
    if latin >= 6 and (latin / max(1, letters) >= 0.25 or not langs):
        langs.append("en")
    return langs or ["en"]


def refine_phone(text: str, start: int, end: int, score: float):
    """Presidio's phone recognizer accepts any digit run that is a *possible* number (timestamps,
    barcodes). Keep only spans that look written as a phone number: '+' prefix or digit-group separators."""
    span = text[start:end]
    digits = sum(c.isdigit() for c in span)
    if digits < 7 or digits > 15:
        return None
    if span.startswith("+") or any(c in span for c in " -()."):
        return start, end, score, {}
    return None


def refine_entity(etype, text, s, e, score):
    """Returns (start, end, score, notes) or None to drop the hit."""
    if etype == "PHONE_NUMBER":
        return refine_phone(text, s, e, score)
    if etype == "EMAIL_ADDRESS":
        return (s, e, score, {}) if "@" in text[s:e] else None
    if etype in ("CREDIT_CARD", "BANK_ACCOUNT", "NATIONAL_ID", "PASSPORT", "DRIVER_LICENSE", "IBAN", "MEDICAL_LICENSE"):
        span = text[s:e]
        return (s, e, score, {}) if sum(c.isdigit() for c in span) >= 5 else None
    return s, e, score, {}
