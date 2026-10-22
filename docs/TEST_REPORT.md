# Test report

Run on 2026-10-22, Linux x86_64 (4 vCPU), Rust 1.97, Python 3.13. Every command below was executed; counts are
what the runner printed. Nothing in the pipeline is mocked: the integration tests call the real rule engine, the
real SQLite store, the real Presidio service and (for parity) the real upstream Gitleaks code.

## Summary

| Suite | Command | Result |
|---|---|---|
| Rust unit + integration (workspace) | `cargo test --workspace` | **73 passed, 0 failed** |
| Gitleaks parity against upstream (real Go library, `gl_difftool`) | `cargo test -p dlp-storage --test gitleaks_parity -- --nocapture` | **6 289 / 6 289 identical** (0 differing) |
| Hyperscan vs portable regex backend | `cargo test -p dlp-engine --test backend_consistency` | identical results |
| HTTP API (real server, real NLP service) | `DLP_NLP_URL=http://127.0.0.1:8791 scripts/linux/run_api_tests.sh` | **21 passed, 0 skipped** |
| C ABI (multithreaded, via `.so`) | `build/bin/test_ffi` (built by `scripts/linux/build.sh`) | `native ABI tests passed` |
| NLP service Python | `pytest services/nlp/tests` | **4 passed** |
| Accuracy | `benchmarks/accuracy/eval.py` | see ACCURACY_REPORT.md |
| Performance / soak | `benchmarks/perf/run_perf.py` | see PERFORMANCE_REPORT.md (600 s + 240 s soak, 0 errors) |
| Dependency vulnerabilities | `cargo audit`, `pip-audit` | 0 known vulnerabilities (THIRD_PARTY.md) |

The Gitleaks parity corpus and expected output are generated locally (`scripts/prepare_test_data.sh --gitleaks`) and
are not committed: they contain key-shaped strings that GitHub push protection rejects. The test needs them and fails
loudly (it does not skip) when they are missing.

## The task's scenarios

| Scenario | Where verified | Result |
|---|---|---|
| A. Chinese phone masking | `engine_flow::scenario_a_cn_phone_masked`, API `test_scenario_a_phone` | phone masked to `138****8000`; the name `张三` is reported only because a rule fired (`cn-name-possessive`), not hard-coded |
| B. English PII ("Alice" + e-mail) | API `test_presidio_recognizers_run_alongside_rules`, `test_names_come_from_rules_not_a_model` | **e-mail detected and masked; the name "Alice" is NOT detected**. The original scenario expected NER to judge the name; NER/model detection was removed by decision, so this part of B is intentionally not met (KNOWN_ISSUES #1) |
| C. API keys | `engine_flow::scenario_c_credentials`, API `test_scenario_c_credential_redacted_not_refused` | synthetic keys detected as credentials and redacted (desensitized by default; `block` is opt-in) |
| D. Two-way anonymization | `engine_flow::scenario_d_roundtrip_and_attacks`, API `test_scenario_d_roundtrip_and_attacks`, `issued_placeholders_are_shielded_but_cannot_hide_secrets` | round trip restores authorised placeholders; cross-session restore fails, forged placeholders are not restored, missing scope is refused, expired vault entries are not restored |
| E. Model response contains sensitive data | `engine_flow::scenario_e_model_response_is_checked_independently` | response checked independently with the response policy |
| F. Streaming, split across SSE chunks | `stream::scenario_f_*`, `byte_by_byte_crlf_and_multibyte`, `window_mode_never_leaks_entity_straddling_release_point`, API `test_scenario_f_*` | in strict mode nothing sensitive is released before the verdict; byte-by-byte delivery and CRLF/multibyte splits are covered |
| G. Rule hot reload | `engine_flow::scenario_g_hot_reload_atomic_and_rollback`, `reload_under_concurrent_load_never_errors` | a changed rule is live without restart; an invalid rule never replaces the running set; 0 errors with a reload every 3 s under load (perf group E) |
| H. C/C++ caller | `examples/c`, `examples/cpp`, `tests/native/test_ffi.c` | real detection and masking through the shared library |
| I. Performance | PERFORMANCE_REPORT.md | QPS, P95/P99, CPU, memory, detector combination stated per row |

## What the robustness tests cover (`crates/dlp-engine/tests/robustness.rs`)

* 300 rounds of random bytes / SSE fragments into the stream scanner in strict and window mode: no panic, and no raw
  phone number reaches the output as a standalone value. **This test found a real leak** (SSE `event:`, `id:` and
  comment fields, and non-JSON data events, were forwarded unscanned); fixed and covered by
  `stream::sse_metadata_fields_and_non_json_events_are_scanned_too`.
* 400 random JSON bodies: structure preserved, only string leaves change, never an error.
* 200-level nesting, 1 MiB pathological regex input (linear time, no ReDoS), hostile custom rules
  (`(a+)+$`, `a{1000}{1000}`, 5 000 open parentheses, bad classes, 20 kB patterns): rejected or linear-time, service stays up.
* Oversized SSE event and unterminated streams fail closed.

## Not covered

* Windows: the cross-compiled CLI/FFI ran under wine only; MSVC build and PowerShell scripts were not run (KNOWN_ISSUES #11).
* No fuzzing beyond the random tests above, no third-party penetration test.
* Accuracy numbers come from a synthetic dataset (ACCURACY_REPORT.md, "Threats to validity").
* The parity test needs the locally generated corpus; CI must run `scripts/prepare_test_data.sh --gitleaks` first.
