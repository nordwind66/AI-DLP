# Third-party components

Pinned in `third_party/manifest.toml`; license texts in `licenses/`; summary in `NOTICE`. (Full table with maintenance risk and
vulnerability scan results is completed in the final report.)

| component | version / revision | license | use | where |
|---|---|---|---|---|
| presidio-analyzer | 2.2.364 / `4f0e236` | MIT (+MS NOTICE) | runtime, NLP service | services/nlp |
| presidio-anonymizer | 2.2.364 | MIT | **dev/verification only** | tests/m1 |
| LLM Guard | 0.3.16 / `168c103` (archived) | MIT | design + algorithms ported; not a dependency | docs/RESEARCH.md §2 |
| Gitleaks | main / `b58d3f1` | MIT | rules (rules/gitleaks.toml), algorithm re-implemented; binary only for parity tests | rules/, crates/dlp-rules |
| spaCy | 3.8.16 | MIT | blank tokenizer-only pipeline for Presidio's NlpEngine; no trained models | services/nlp |
| phonenumbers | 9.0.41 | Apache-2.0 | Presidio phone recognizer (libphonenumber port) | services/nlp |

No statistical / ML model, model weights or trained spaCy pipeline is used or shipped; the NLP service needs no `models/` directory.
