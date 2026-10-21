"""Unit tests for the structural post-filters (no models involved): python -m pytest services/nlp/tests"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from dlp_nlp import cjk


def test_phone_and_email_filters():
    assert cjk.refine_phone("时间戳 1698339816995", 4, 17, 0.4) is None
    assert cjk.refine_phone("call +1 212-555-0198", 5, 20, 0.4) is not None
    assert cjk.refine_entity("EMAIL_ADDRESS", "邮箱必须唯一", 0, 6, 0.9) is None
    assert cjk.refine_entity("CREDIT_CARD", "1234", 0, 4, 0.9) is None


def test_language_heuristic():
    assert cjk.detect_langs("今天天气不错") == ["zh"]
    assert cjk.detect_langs("hello world again") == ["en"]
    assert set(cjk.detect_langs("请联系 Alice Johnson 处理")) == {"zh", "en"}
