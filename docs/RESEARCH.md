# Source study of the four projects, and what is reused where

> **HISTORICAL RESEARCH - model options were evaluated and then DROPPED.** This document records the source study done
> before the product scope was fixed. GLiNER, LLM/transformer-based and other statistical / ML detection options (including
> Presidio's spaCy NER, spaCy trained models, ONNX inference) were evaluated here and then **removed from the product by
> decision**, because the user requirement is *no model-based detection*: detection must be deterministic, auditable and
> reproducible, and ship no model weights (no torch / transformers / onnxruntime / Hugging Face downloads). The shipped NLP
> service runs **only Presidio's deterministic recognizers** (regex + checksum + libphonenumber) on a blank, tokenizer-only
> spaCy pipeline; person / organization / address detection is rule-based in Rust (see docs/KNOWN_ISSUES.md #1). Sections 1
> (partly) and 3 and the GLiNER/ONNX rows of the matrix describe what was measured, not what ships. The research facts,
> licences and measurements below are kept unchanged for traceability.

All sources were cloned at the pinned commits (third_party/manifest.toml), read, and **executed** (verification scripts in
`tests/m1/`, outputs in `docs/m1_*.txt`). Licenses were read from the repositories and the Hugging Face model cards.

| project | commit | version | license | notes |
|---|---|---|---|---|
| Presidio | `4f0e236` (2026-10-19) | analyzer/anonymizer 2.2.364 | MIT (+ Microsoft third-party NOTICE, kept in `licenses/presidio-NOTICE.txt`) | active |
| LLM Guard | `168c103` (2026-07-09, "Archiving Project") | 0.3.16 | MIT | **archived**, requires Python < 3.13, pins `transformers==4.51.3` |
| GLiNER | `f3c9457` (2026-10-05) | 0.2.29 | Apache-2.0 | active |
| Gitleaks | `b58d3f1` (2026-07-22) | v8 main, config `minVersion v8.25.0` | MIT | active |

## 1. Presidio (`presidio-analyzer`, `presidio-anonymizer`)

**Code entry points read** – `analyzer_engine.py:35 AnalyzerEngine`, `:169 analyze()` (get recognizers from the registry → NLP artifacts → run each recognizer →
`_enhance_using_context` (`:299`) → drop low scores → `EntityRecognizer.remove_duplicates` (`entity_recognizer.py:277`) → allow-list); `recognizer_registry.py:31 RecognizerRegistry`
(`load_predefined_recognizers :117`, `get_recognizers :187`); `pattern_recognizer.py:24 PatternRecognizer` (`analyze :97`, `validate_result :136` – the checksum hook, e.g.
`credit_card_recognizer.py:63` Luhn); `phone_recognizer.py:15 PhoneRecognizer` (phonenumbers, leniency); `lemma_context_aware_enhancer.py:12` (score boost from nearby lemma context);
`predefined_recognizers/ner/gliner_recognizer.py` (Presidio's own GLiNER wrapper); anonymizer: `anonymizer_engine.py:21`, `operators/` (replace, mask, redact, hash, encrypt, keep…),
`text_replace_builder.py:8`, `recognizer_result.py:93 has_conflict / :126 intersects`.

**The seven questions**

1. *Identify PII*: `AnalyzerEngine` over registered recognizers; verified by `tests/m1/verify_presidio.py` (EN: PERSON/EMAIL/PHONE/CREDIT_CARD found with scores; ZH below).
2. *External NER*: Presidio ships a `GLiNERRecognizer` (chunking by characters, `entity_mapping`). We do **not** load it – GLiNER is a separate detector in the same NLP service, called once per text, so
   the model is not run twice and its output gets the same CJK refinement as spaCy's.
3. *Custom Chinese rules*: Presidio would take `PatternRecognizer(supported_language="zh", …)` objects (or YAML). We keep them in **SQLite + Rust** instead – checksum validators, context windows, hot reload, versioning,
   audit and the same engine as the credential rules. Presidio's contribution for Chinese is its spaCy NER and phone/credit-card/IBAN/crypto recognizers.
4. *Chinese names/addresses*: measured, not assumed. Presidio `zh` has no Chinese-specific recognizers (entity list in `docs/m1_presidio_verify.txt`), the default `PhoneRecognizer` misses `13800138000` (regions not including CN – we register it with `CN,US,GB,HK,TW,SG,JP,KR,DE,FR,IN,AU,CA`),
   and `zh_core_web_sm` tags "手机号" and the local part of an e-mail as PERSON and gives a flat 0.85. Hence surname validation, boundary refinement, place-name exclusion and a 0.6 cap on uncalibrated spaCy scores
   (`services/nlp/dlp_nlp/cjk.py`), and the contextual Chinese-name rules.
5. *Reuse anonymization*: studied (operators + `TextReplaceBuilder`: back-to-front replacement), mirrored in Rust (`mask.rs`: `chars_to_mask`/`from_end` semantics → per-type maskers; `executor.rs`: single pass left-to-right), but **not called** – see ARCHITECTURE §6.3.
6. *Avoid Presidio/GLiNER duplicates*: both return `Entity` objects; same-type overlaps are fused (evidence max, capped noisy-OR), model-vs-model never double-counts; `EntityRecognizer.remove_duplicates` is the analogue of `merge_entities` step 1.
7. *Model loading / performance*: engine + registry built once at start (4.5 s, warm-up call), spaCy `en_core_web_sm`+`zh_core_web_sm` resident; per call ≈ 6–10 ms for short texts (docs/PERFORMANCE_REPORT.md). `entities` filter limits recognizers per call.

## 2. LLM Guard – exactly what was reused

The package is not a dependency (archived; torch/transformers 4.51 pins; Python < 3.13). Files studied and executed in an isolated venv: `tests/m1/verify_llmguard.py`.

| LLM Guard (file:function) | what it does | reused here |
|---|---|---|
| `input_scanners/anonymize.py:232 _get_entity_placeholder` | `[REDACTED_<TYPE>_<n>]` | placeholder scheme `[<TYPE>_<n>]` (shorter, matches the spec example) – `vault.rs: placeholder_for` |
| `anonymize.py:_anonymize` (value → index map, `vault_entities` lookup, next free index) | the **same value gets the same placeholder**; indices per type; reuse of existing vault entries across turns | `vault.rs`: HMAC-keyed `by_value` map + per-type counters inside a session; verified `[PERSON_1]` reuse across turns (`engine_flow.rs::issued_placeholders_are_shielded…`) |
| `anonymize.py:129 _remove_conflicts_and_get_text_manipulation_data` (merge same-type overlaps; drop contained/conflicting; trim partial overlaps by score) | 3-step conflict resolution | `dlp-core/src/merge.rs` steps 2–3 (union same type, greedy by rank, trim losing *model* spans) – with deterministic-first ranking instead of score-first |
| `anonymize.py:213 _merge_entities_with_whitespace_between` | merge adjacent same-type entities separated by spaces | `merge.rs: merge_adjacent_same_type` (restricted to PERSON/ORGANIZATION/ADDRESS/LOCATION) |
| `anonymize.py:scan` order: analyze → resolve conflicts → merge → anonymize → store | pipeline order | `engine.rs: finalize` |
| `output_scanners/deanonymize.py:29 _match_exact` | restore by exact placeholder | `vault.rs: deanonymize` – but **single pass** |
| `deanonymize.py:44/…:_match_case_insensitive, _match_fuzzy (max_l_dist=3)` | fuzzy/case-insensitive restore | **rejected**: restores unissued strings (reproduced: `REDACTED_PERSON_9` → a real name) |
| `deanonymize.py:_match_exact` is a loop of `str.replace` | chained replacement | **rejected**: a restored value containing another placeholder is expanded again (reproduced). Ours scans the model text once and never rescans restored values |
| `vault.py:4 Vault` (list of tuples; `placeholder_exists`) | storage | **replaced**: tenant+session keyed, owner-bound, TTL, entry/size limits, `Zeroizing` values, HMAC value index, no logging, sweeper |
| `input_scanners/secrets.py:419-457 redact_value` (`partial`, `all`, `hash` = md5) | secret redaction modes | `mask.rs` partial masking; `hash` (md5, rainbow-able) not adopted – fixed labels are used for credentials |
| `input_scanners/anonymize_helpers/*` (regex patterns, ner_mapping, faker) | extra recognizers, fake values | not used (faker substitutes were considered unsuitable: they leak "realistic" data and break restore) |

Answers to the task's LLM Guard questions: (1) prompt anonymization → `/v1/anonymize`; (2) response-side data → independent detection of the response before any restore; (3) recovery → `/v1/deanonymize`, single-pass exact; (4) vault stores `(placeholder → value)` per `(tenant, session)` in memory only;
(5) cross-session conflicts → impossible by construction (separate maps; `[PERSON_1]` in two sessions are different entries; optional `nonce_placeholders` makes the text itself session-specific);
(6) unauthorized restore → scope `deanonymize` + owner check (+ `vault:admin`), foreign/expired/unknown sessions all 404, restore only for configured directions (default: response, never tool inputs);
(7) semantic consistency → same value ⇒ same placeholder across the whole conversation, all JSON fields share one session, credentials/irreversible types are never put in the vault.

## 3. GLiNER

**Code read** – `gliner/model.py:1599 from_pretrained` (HF repo or local dir; `load_onnx_model`, `local_files_only`), `:3139 predict_entities`, `:3180 batch_predict_entities`
(span scoring, `flat_ner`, `threshold`, returns char offsets), `:2167 export_to_onnx`, `data_processing/tokenizer.py` (**`WhitespaceTokenSplitter`: regex `\w+(?:[-_]\w+)*|\S`**), `train.py` (training entry).

**Models** (license from the HF cards): `urchade/gliner_multi_pii-v1` – Apache-2.0, mdeberta-v3-base backbone (MIT), trained on `urchade/synthetic-pii-ner-mistral-v1` (synthetic, LLM-generated – training-data provenance to be cleared by legal for commercial use);
`urchade/gliner_multi-v2.1` – Apache-2.0 (`pile-mistral-v0.1`). **Excluded: `urchade/gliner_multi`, `gliner_base`, `gliner_small-v1` (CC-BY-NC-4.0, non-commercial); `nvidia/gliner-PII` (NVIDIA Open Model License, English).**
Apache-2.0 alternatives checked: `knowledgator/gliner-pii-*` (English DeBERTa-v3), `E3-JSI/gliner-multi-pii-domains-v1` (European languages), `gliner_large-v2.1` (English-centric backbone). None adds Chinese.

**Chinese reality check** (not assumed): see `docs/m1_gliner_verify.txt` and `docs/ACCURACY_REPORT.md`. English is excellent (pii-v1: person/email/phone/address/passport at 0.97–1.00). Chinese: the span for
"张三的手机号是13800138000" is the *whole phrase*; person recall on the Chinese subset is 0.51 at F1 0.67; organization recall 0. Label wording (English, Chinese, "person name", "姓名", combos), thresholds and clause segmentation were swept
(`benchmarks/accuracy/gliner_zh_probe.py`, 26 configurations for pii-v1): the best configuration gained +0.02 F1 over plain `["person"]`; several common wordings are far worse (recall 0.07–0.36).
Root cause found in the source: the default word splitter treats a run of Han characters as **one word**; spans can only start and end on word boundaries. `services/nlp/dlp_nlp/splitter.py` installs a character-level Han splitter (results in ACCURACY_REPORT §GLiNER-Chinese).
A Chinese fine-tuning recipe is in `docs/ZH_FINETUNE.md`.

**ONNX / CPU performance**: torch CPU is the default (measured in the performance report); ONNX export is available (`export_to_onnx`) and was evaluated, see PERFORMANCE_REPORT.

## 4. Gitleaks

**Code read** – `config/config.go:109 Translate` (TOML → rules, allowlists incl. `targetRules`, `required`), `:318 parseAllowlist`; `config/rule.go:12 Rule`, `:57 Required`, `:64 Validate`; `config/allowlist.go:70 Validate`, `:149 RegexAllowed`, `:161 ContainsStopWord`;
`detect/detect.go:276 DetectContext` (keyword prefilter → per-rule → decode passes), `:371 detectRule`, `:580 processRequiredRules`; `detect/utils.go:117 shannonEntropy`, `:137 filter`; `detect/codec/*` (base64/hex/percent/unicode decoding);
`cmd/generate/config/rules/*.go` (each rule has TP/FP samples validated by `utils.Validate`).

The default config: 222 rules; 130 with `entropy`, 221 with `keywords`, 9 with allowlists (4 regexTarget≠secret, 1 AND), 1 `secretGroup`, 1 path-only, 0 `required`, one global allowlist (paths, 13 regexes, 2 stop-words).
Mapping and the 6289/6289 differential result: **docs/GITLEAKS_PARITY.md**. Rule classes for the spec's categories (AWS/GCP/Azure/Alibaba/Tencent cloud keys, OpenAI/Anthropic/HF/Cohere… LLM keys, GitHub/GitLab/Slack tokens, JWT, private keys, DB, OAuth, generic) are
mapped to entity types by `dlp-storage/src/gitleaks.rs: classify`.

## 5. Capability / reuse matrix

| capability | Presidio | LLM Guard | GLiNER | Gitleaks | this repo |
|---|---|---|---|---|---|
| structured PII (phone/email/card/IBAN/crypto/US ids) | **runtime** (analyzer) | – | – | – | + Chinese rules in SQLite |
| Chinese ID/mobile/USCC/bank card with checksum | none for zh | none | – | – | **own** (`validators.rs`) |
| names / orgs / addresses (non-fixed) | spaCy NER (evaluated, **dropped**) | – | evaluated, **dropped** | – | contextual rules + dictionaries + `cn-address` only |
| API keys / tokens / private keys | – | detect-secrets (not used) | – | **rules + algorithm ported, rules imported** | SecretDetector |
| placeholder anonymization / restore | operators (studied) | **ported & hardened** | – | – | executor + Vault |
| conflict resolution between engines | `remove_duplicates` (analogue) | **ported (3 steps + whitespace merge)** | – | `filter()` (generic vs specific, ported) | `merge.rs` |
| ONNX/CPU inference | onnxruntime optional | optional | evaluated, **dropped** | – | not used |
