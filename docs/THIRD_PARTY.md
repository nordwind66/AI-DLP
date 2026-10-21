# Third-party components

Pinned in `third_party/manifest.toml`; license texts in `licenses/`; summary in `NOTICE`. (Full table with maintenance risk and
vulnerability scan results is completed in the final report.)

| component | version / revision | license | use | where |
|---|---|---|---|---|
| presidio-analyzer | 2.2.364 / `4f0e236` | MIT (+MS NOTICE) | runtime, NLP service | services/nlp |
| presidio-anonymizer | 2.2.364 | MIT | **dev/verification only** | tests/m1 |
| LLM Guard | 0.3.16 / `168c103` (archived) | MIT | design + algorithms ported; not a dependency | docs/RESEARCH.md §2 |
| GLiNER | 0.2.29 / `f3c9457` | Apache-2.0 | runtime, NLP service | services/nlp |
| Gitleaks | main / `b58d3f1` | MIT | rules (rules/gitleaks.toml), algorithm re-implemented; binary only for parity tests | rules/, crates/dlp-rules |
| urchade/gliner_multi_pii-v1 | `1fcf13e8` | Apache-2.0 | model weights (converted to safetensors) | models/ |
| urchade/gliner_multi-v2.1 | `443d26d6` | Apache-2.0 | alternative model | models/ |
| microsoft/mdeberta-v3-base | `a0484667` | MIT | tokenizer/config only | models/hf_home |
| spaCy en/zh_core_web_sm | 3.8.0 | MIT | Presidio NER | services/nlp |
| Excluded | `urchade/gliner_multi`, `gliner_base`, `gliner_small-v1` (CC-BY-NC-4.0, non-commercial); `nvidia/gliner-PII` (NVIDIA Open Model License) | | **must not ship** | |
