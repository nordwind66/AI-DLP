"""Unit tests for NER post-filters (no models needed): python -m pytest services/nlp/tests"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from dlp_nlp import cjk


def test_cjk_person_boundary_refinement():
    t = "张三的手机号是13800138000"
    assert cjk.refine_cjk_person(t, 0, len(t), 0.99)[:2] == (0, 2)       # model span engulfed context + phone
    assert cjk.refine_cjk_person("手机号", 0, 3, 0.85) is None             # no surname, not very sure
    assert cjk.refine_cjk_person("欧阳娜娜", 0, 4, 0.7)[:2] == (0, 4)       # compound surname


def test_latin_filters_drop_identifiers_and_pronouns():
    for w in ["Email", "SLACK_BOT_TOKEN", "jwt", "everyone", "Her", "HF_TOKEN"]:
        assert cjk.refine_latin_person(w, 0, len(w), 0.95) is None, w
    assert cjk.refine_latin_person("Alice Johnson", 0, 13, 0.6) is not None


def test_org_phone_email_filters():
    assert cjk.refine_org("TCP and UDP", 0, 3, 0.85) is None
    assert cjk.refine_org("Acme Corporation", 0, 16, 0.8) is not None
    assert cjk.refine_org("公司地址是", 0, 5, 0.85) is None
    assert cjk.refine_phone("时间戳 1698339816995", 4, 17, 0.4) is None
    assert cjk.refine_phone("call +1 212-555-0198", 5, 20, 0.4) is not None
    assert cjk.refine_entity("EMAIL_ADDRESS", "邮箱必须唯一", 0, 6, 0.9) is None


def test_place_names_that_start_with_a_surname():
    assert cjk.refine_entity("PERSON", "张家界风景区", 0, 3, 0.95) is None
    assert cjk.refine_entity("PERSON", "王小明来了", 0, 3, 0.95) is not None


def test_language_heuristic():
    assert cjk.detect_langs("今天天气不错") == ["zh"]
    assert cjk.detect_langs("hello world again") == ["en"]
    assert set(cjk.detect_langs("请联系 Alice Johnson 处理")) == {"zh", "en"}
