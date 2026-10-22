# Unified AI DLP Engine

Detects sensitive data in LLM **prompts, responses, tool calls and SSE streams** and **desensitizes** it
(mask / redact / replace / reversible anonymization). Blocking exists but is an explicit opt-in; every built-in policy
except `block-secrets` sanitizes and forwards.

It integrates three open-source projects where each is strongest (no statistical / ML model is used anywhere; detection is deterministic):

| | role here |
|---|---|
| [Microsoft Presidio](https://github.com/data-privacy-stack/presidio) | deterministic PII recognizers only (regex + checksum + libphonenumber: phone, email, credit card, IBAN, crypto, US ids) on a blank tokenizer-only spaCy pipeline (runtime, Python NLP service) |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | 222 credential rules imported into SQLite, detection algorithm re-implemented in Rust — **6289/6289 identical to the real binary** |
| [LLM Guard](https://github.com/protectai/llm-guard) | placeholder anonymization design ported to Rust; its Vault replaced by a tenant/session-scoped, owner-bound, expiring one |

Rust core (rules, secrets, dictionaries, policy, vault, protocol, streaming, SQLite, C ABI, REST) + a separate Python NLP
service for Presidio's deterministic recognizers (no ML models, no `models/` directory, loads in under a second). CPU only, fully offline at runtime, Linux x86_64 and Windows x64.

```
张三的手机号是13800138000，key=AKIAZ3XQKVN5TLWM7EPD
→ [REDACTED_PERSON]的手机号是138****8000，key=[REDACTED_CLOUD_CREDENTIAL]
```

## Quick start (Linux)

```bash
scripts/linux/build.sh                                         # Rust workspace + C/C++ examples + native test
build/bin/dlp --db ai_dlp.db --rules-dir rules init            # SQLite rule DB: 222 gitleaks + built-in rules + policies
build/bin/dlp --db ai_dlp.db detect -m sanitize -t '张三的手机号是13800138000。'
build/bin/dlp-server genkey                                    # then write keys.json and:
build/bin/dlp-server --db ai_dlp.db --api-keys keys.json --nlp-url http://127.0.0.1:8791
```
Presidio NLP service (optional, adds phone/email/credit card/IBAN/crypto/US-id recognizers; person/organization/address come from Rust rules, not from this service): see [docs/BUILD_LINUX.md](docs/BUILD_LINUX.md). Windows: [docs/BUILD_WINDOWS.md](docs/BUILD_WINDOWS.md).

## Documentation

| | |
|---|---|
| [ARCHITECTURE](docs/ARCHITECTURE.md) | layers, pipeline, merge, failure modes, decisions and deviations |
| [RESEARCH](docs/RESEARCH.md) | source study of the four projects (historical; includes evaluated-and-dropped model options), exact reuse matrix (file/function level) |
| [API](docs/API.md) · [openapi.yaml](docs/openapi.yaml) · [C_ABI](docs/C_ABI.md) | HTTP, C ABI (`include/ai_dlp.h`) |
| [DATABASE](docs/DATABASE.md) | SQLite rule/policy schema, importer, versions, audit |
| [ACCURACY_REPORT](docs/ACCURACY_REPORT.md) · [PERFORMANCE_REPORT](docs/PERFORMANCE_REPORT.md) · [TEST_REPORT](docs/TEST_REPORT.md) | measured results |
| [PROGRESS](docs/PROGRESS.md) · [KNOWN_ISSUES](docs/KNOWN_ISSUES.md) | status, decisions, limits |
| [GITLEAKS_PARITY](docs/GITLEAKS_PARITY.md) | differential test against upstream gitleaks |
| [BUILD_LINUX](docs/BUILD_LINUX.md) · [BUILD_WINDOWS](docs/BUILD_WINDOWS.md) | build / run / test |
| `docs/THIRD_PARTY.md`, `third_party/manifest.toml`, `licenses/`, `NOTICE` | components, versions, commits, licenses |

## Layout

`crates/` (dlp-core, dlp-rules, dlp-storage, dlp-policy, dlp-anonymizer, dlp-detectors, dlp-protocol, dlp-stream, dlp-engine, dlp-ffi) ·
`apps/` (dlp-server, dlp-cli) · `tools/gitleaks-importer` · `services/nlp` (Presidio deterministic recognizers) · `rules/` (gitleaks.toml, builtin.toml) ·
`database/` · `include/ai_dlp.h` · `examples/{c,cpp,python}` · `tests/` · `benchmarks/` · `scripts/{linux,windows}` · `docs/`.

## Status

All milestones M1–M7 are implemented and verified on Linux x86_64 ([PROGRESS](docs/PROGRESS.md), [TEST_REPORT](docs/TEST_REPORT.md)): 73 Rust tests, 21 API tests,
C ABI test, Gitleaks parity 6 289/6 289, accuracy and performance reports ([ACCURACY](docs/ACCURACY_REPORT.md), [PERFORMANCE](docs/PERFORMANCE_REPORT.md)).
Honest limits are in [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md). Notably: there is **no ML model** in the pipeline, so person/organization/free-form address detection
(Chinese and English) is rule-based only (labelled and possessive patterns, dictionaries, province-anchored addresses) and unlabelled names and free-form company names will be missed;
Gitleaks' base64/hex decoding passes are not implemented; the MSVC build and PowerShell scripts could not be run in the development environment
(the mingw cross-build was executed under Wine).

License: Apache-2.0 (see NOTICE for third-party components).
