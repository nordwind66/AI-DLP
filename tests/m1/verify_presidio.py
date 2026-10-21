"""M1: verify Presidio Analyzer/Anonymizer really run here (no mocks) on EN + ZH text.
Prints entity types and offsets only (no raw values beyond the synthetic test strings)."""
import time, json
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

import presidio_analyzer, presidio_anonymizer
print("presidio-analyzer", presidio_analyzer.__name__)

conf = {"nlp_engine_name": "spacy", "models": [
    {"lang_code": "en", "model_name": "en_core_web_sm"},
    {"lang_code": "zh", "model_name": "zh_core_web_sm"}]}
t0 = time.time()
nlp = NlpEngineProvider(nlp_configuration=conf).create_engine()
registry = RecognizerRegistry(supported_languages=["en", "zh"])
registry.load_predefined_recognizers(languages=["en", "zh"], nlp_engine=nlp)
analyzer = AnalyzerEngine(nlp_engine=nlp, registry=registry, supported_languages=["en", "zh"])
print("load_s", round(time.time() - t0, 2))
print("supported entities en:", sorted(analyzer.get_supported_entities("en"))[:40])
print("supported entities zh:", sorted(analyzer.get_supported_entities("zh")))

cases = [
    ("en", "Please contact Alice Johnson at alice@example.com or +1 212-555-0198. Card 4111 1111 1111 1111."),
    ("zh", "张三的手机号是13800138000，邮箱 zhangsan@example.com，住在北京市海淀区中关村大街1号。"),
    ("zh", "请帮李四分析客户资料，他在腾讯公司工作。"),
]
anon = AnonymizerEngine()
for lang, text in cases:
    t = time.time()
    res = analyzer.analyze(text=text, language=lang)
    ms = (time.time() - t) * 1000
    print(f"--- [{lang}] {ms:.1f} ms  text_len={len(text)}")
    for r in sorted(res, key=lambda r: r.start):
        print(f"  {r.entity_type:16s} [{r.start:3d},{r.end:3d}) score={r.score:.2f} rec={r.recognition_metadata.get('recognizer_name')}")
    out = anon.anonymize(text=text, analyzer_results=res,
                         operators={"DEFAULT": OperatorConfig("replace", {"new_value": "<X>"}),
                                    "PHONE_NUMBER": OperatorConfig("mask", {"chars_to_mask": 4, "masking_char": "*", "from_end": True})})
    print("  anonymized:", out.text)
