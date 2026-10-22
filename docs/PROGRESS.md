# Progress

Status per milestone. "Verified" means executed in this repository with the result in TEST_REPORT.md; "written" means
code exists but has not been run.

| Milestone | Scope | Status | Evidence |
|---|---|---|---|
| M1 | Source research, reuse matrix, tool-chain check, real runs of Presidio / LLM Guard / Gitleaks | **done** (GLiNER later removed by decision) | docs/RESEARCH.md, docs/m1_llmguard_verify.txt |
| M2 | Rust core: SQLite rules, Gitleaks import, rule detectors, merge, masking executor, policy | **verified** | `cargo test --workspace` (73), Gitleaks parity 6 289/6 289 |
| M3 | Presidio recognizers service (NLP), detector client, degraded/fail modes | **verified** | API tests, perf group D; no ML model (decision) |
| M4 | HTTP API + OpenAPI, protocol parsing (OpenAI chat/responses, Anthropic, tool calls), vault / reversible anonymization | **verified** | `tests/api`, `engine_flow`, `protocol` |
| M5 | SSE streaming (strict, window), C ABI + C/C++ examples | **verified** (window mode effectively unavailable with the default rules, KNOWN_ISSUES #7) | `stream`, `test_ffi` |
| M6 | Accuracy, concurrency, soak, hot reload | **verified** on Linux | ACCURACY_REPORT, PERFORMANCE_REPORT |
| M7 | Documentation, scripts, supply chain | **done**; Windows MSVC/PowerShell **written, not run** | docs/, scripts/, THIRD_PARTY.md |

## Decisions that changed the plan

1. **Desensitize, don't block** (user): default actions mask/redact/anonymize; `BLOCK` is opt-in; unmodifiable signed
   stream blocks are dropped rather than refusing the whole response.
2. **No model-based detection** (user): GLiNER and spaCy NER removed; the NLP service runs Presidio's deterministic
   recognizers only. Consequence: names and organizations are found by rules/dictionaries only (ACCURACY_REPORT.md).
3. Generated key-shaped test data is not committed (GitHub secret scanning); it is produced by scripts.

## Open items

See KNOWN_ISSUES.md. The main ones: rule-only names/organizations, Gitleaks decoding passes, window streaming with
default rules, Windows run-through on a real host, in-memory-only vault, NLP-path throughput.
