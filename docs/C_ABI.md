# C ABI (`include/ai_dlp.h`)

Artifacts: Linux `libai_dlp.so` (+ `libai_dlp.a`), Windows `ai_dlp.dll` + import library `ai_dlp.dll.lib`/`libai_dlp.dll.a`.
ABI version `DLP_ABI_VERSION = 1` (`dlp_abi_version()`); additive changes keep it, breaking changes bump it.

## Contract

| topic | rule |
|---|---|
| data | UTF-8 JSON in/out, **explicit lengths** (no NUL needed). Request schema = HTTP API schema (docs/API.md). No Rust/Python object ever crosses the boundary |
| ownership | every call that produces output writes a `dlp_result_t*` that the **library owns** until `dlp_free_result()` (`NULL` is a no-op). `data` is NUL-terminated JSON, `len` excludes the NUL. The same holds for failures: `{"error":{"code":N,"message":"…"}}` |
| errors | return value == `result->code`: `0 OK`, `1 INVALID_ARG` (NULL / bad length), `2 INVALID_INPUT` (bad JSON, invalid UTF-8, bad field), `3 TOO_LARGE`, `4 DETECTOR_UNAVAILABLE`, `5 TIMEOUT`, `6 RULES`, `7 STORAGE`, `8 POLICY`, `9 VAULT`, `10 FORBIDDEN`, `11 NOT_FOUND` (policy / vault session), `98 PANIC` (isolated), `99 INTERNAL`. Messages never contain request text |
| threads | `dlp_engine_t` is thread-safe (any number of concurrent `dlp_detect/sanitize/anonymize/deanonymize/reload/capabilities`). `dlp_destroy` must not race with other calls on that handle. `dlp_stream_t` is single-threaded |
| panics | every entry point runs under `catch_unwind`; nothing unwinds into C/C++ (the crates are built with `panic = "unwind"` for this reason) |
| memory | inputs are only read during the call; the library keeps no pointers into them |
| trust | in-process component: it trusts its host. `tenant_id` / `subject` in the request choose the vault namespace and all scopes are granted. Put `dlp-server` in front for untrusted callers |
| NLP dependency | the library itself contains rules/secrets/dictionaries/policy/vault/protocol/stream. Presidio and GLiNER are reached through `nlp_url` (the Python NLP service). Without it `capabilities.full_capability=false` and detector reports say `not configured` |

## Functions

```c
int  dlp_create(const char* config_json, size_t len, dlp_engine_t** out_engine, dlp_result_t** out_caps);
void dlp_destroy(dlp_engine_t*);
int  dlp_detect   (const dlp_engine_t*, const char* req, size_t len, dlp_result_t** out);   // never modifies text
int  dlp_sanitize (...);                                                                    // mask / redact / replace
int  dlp_anonymize(...);                                                                    // reversible, session vault
int  dlp_deanonymize(...);                                   // {"session_id","text","tenant_id","direction","policy_id","check_response"}
int  dlp_reload_rules(const dlp_engine_t*, dlp_result_t** out);
int  dlp_capabilities(const dlp_engine_t*, dlp_result_t** out);
void dlp_free_result(dlp_result_t*);
int  dlp_stream_open(const dlp_engine_t*, const char* opts, size_t len, dlp_stream_t**, dlp_result_t**);
int  dlp_stream_push(dlp_stream_t*, const uint8_t* data, size_t len, dlp_result_t** out);   // {"output","blocked","stats"}
int  dlp_stream_finish(dlp_stream_t*, dlp_result_t** out);
void dlp_stream_close(dlp_stream_t*);
```

`dlp_create` config: `{"db_path":":memory:"|"rules.db","rules_dir":"rules","nlp_url":"http://127.0.0.1:8791","nlp_token":"",
"use_hyperscan":true,"default_policy":"default","max_text_bytes":4194304,"request_timeout_ms":30000,"vault_ttl_secs":3600,
"nonce_placeholders":false}`. An empty database is bootstrapped from `rules_dir` (gitleaks.toml + builtin.toml).

## Examples

`examples/c/example.c`, `examples/cpp/example.cpp` (RAII wrappers), built and run by `scripts/linux/build.sh`;
`tests/native/test_ffi.c` is the native-interface test (contract, error codes, invalid UTF-8, NULLs, tenant isolation,
streaming, 8 threads × 200 calls). Windows: `scripts/windows/build.ps1`.

```c
dlp_engine_t* e; dlp_result_t* r;
dlp_create("{\"rules_dir\":\"rules\"}", 22, &e, &r); dlp_free_result(r);
const char* q = "{\"text\":\"张三的手机号是13800138000。\",\"policy_id\":\"default\"}";
if (dlp_sanitize(e, q, strlen(q), &r) == DLP_OK) puts(r->data);   // …"sanitized_text":"[REDACTED_PERSON]的手机号是138****8000。"…
dlp_free_result(r); dlp_destroy(e);
```
