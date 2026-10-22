# Third-party components

Pinned in `third_party/manifest.toml`; license texts in `licenses/`; summary in `NOTICE`. 

| component | version / revision | license | use | where |
|---|---|---|---|---|
| presidio-analyzer | 2.2.364 / `4f0e236` | MIT (+MS NOTICE) | runtime, NLP service | services/nlp |
| presidio-anonymizer | 2.2.364 | MIT | **dev/verification only** | tests/m1 |
| LLM Guard | 0.3.16 / `168c103` (archived) | MIT | design + algorithms ported; not a dependency | docs/RESEARCH.md §2 |
| Gitleaks | main / `b58d3f1` | MIT | rules (rules/gitleaks.toml), algorithm re-implemented; binary only for parity tests | rules/, crates/dlp-rules |
| spaCy | 3.8.16 | MIT | blank tokenizer-only pipeline for Presidio's NlpEngine; no trained models | services/nlp |
| phonenumbers | 9.0.41 | Apache-2.0 | Presidio phone recognizer (libphonenumber port) | services/nlp |

No statistical / ML model, model weights or trained spaCy pipeline is used or shipped; the NLP service needs no `models/` directory.

## Python runtime dependencies (`services/nlp/requirements.txt`, all pinned)

| package | version | license | note |
|---|---|---|---|
| presidio-analyzer | 2.2.364 | MIT | maintained by Microsoft; active |
| spaCy | 3.8.16 | MIT | tokenizer only |
| phonenumbers | 9.0.41 | Apache-2.0 | port of Google libphonenumber; active |
| FastAPI / Starlette / uvicorn | 0.156.4 / 1.9.0 / 0.54.0 | MIT / BSD-3 / BSD-3 | HTTP server |
| pydantic / numpy | 2.14.1 / 2.4.6 | MIT / BSD-3 | |

## Rust dependencies

155 third-party crates (`Cargo.lock`, locked builds). Licences: 87 × MIT OR Apache-2.0, 24 × MIT, 18 × Unicode-3.0, 9 × Apache-2.0 OR MIT,
5 × MIT/Apache-2.0, and a handful of other permissive ones (Zlib, ISC, BSD-2/3-Clause, Unlicense OR MIT, Apache-2.0 OR BSL-1.0). **No GPL/LGPL/AGPL/MPL/SSPL
or non-commercial licence** in the dependency tree. Hyperscan (BSD-3-Clause, Intel) is loaded at runtime with `dlopen` if present and is not shipped.

## Vulnerability scan (2026-10-22)

* `cargo audit` 0.22.2, RustSec database of 1 348 advisories, 168 locked crates: **0 vulnerabilities**. It flagged `tokio 1.54.0` as *yanked*; updated to 1.54.1, re-scan clean.
* `pip-audit` on `services/nlp/requirements.txt` (pinned set, `--no-deps`): **no known vulnerabilities**.
* Scans are point-in-time. Re-run `cargo audit` and `pip-audit -r services/nlp/requirements.txt` in CI.

## Maintenance risk

| component | risk | comment |
|---|---|---|
| Gitleaks rules | low | upstream active; rules imported by `tools/gitleaks-importer` and diff-tested (GITLEAKS_PARITY.md) so updates are re-importable |
| Presidio | low–medium | active Microsoft project, but only its deterministic recognizers are used; replaceable by Rust rules |
| LLM Guard | n/a | archived upstream; only algorithms were ported (whitespace-merge of adjacent spans), no runtime dependency |
| Hyperscan | medium | Intel's repo is in maintenance mode (Vectorscan is the active fork); optional prefilter, portable regex path is the fallback and verified identical |
| spaCy | low | used only for tokenization |
