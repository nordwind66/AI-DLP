/*
 * ai_dlp.h - C ABI of the Unified AI DLP Engine.
 *
 * Link against libai_dlp.so (Linux x86_64) or ai_dlp.dll / ai_dlp.dll.lib (Windows x64).
 *
 * Conventions
 *  - All text is UTF-8. Inputs are (pointer, byte length) pairs and need not be NUL-terminated.
 *  - Requests/responses are JSON documents identical to the HTTP API (docs/API.md).
 *  - Every call returns a status code; the dlp_result_t* written to *out always holds valid JSON
 *    (the payload on success, {"error":{"code":N,"message":"..."}} on failure) and must be released
 *    with dlp_free_result(). dlp_free_result(NULL) is a no-op.
 *  - No exception or panic crosses this boundary.
 *  - dlp_engine_t is thread-safe. Do not call dlp_destroy concurrently with other calls on the handle.
 *    dlp_stream_t is NOT thread-safe: use one stream per thread (or serialize access).
 *  - The library trusts its host process (tenant_id / subject come from the caller). It never sends
 *    text anywhere except to the configured loopback NLP service.
 *  - Detection results never contain the matched value (only offsets, types, scores, masked context).
 */
#ifndef AI_DLP_H
#define AI_DLP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32)
#  if defined(AI_DLP_STATIC)
#    define DLP_API
#  elif defined(AI_DLP_BUILDING)
#    define DLP_API __declspec(dllexport)
#  else
#    define DLP_API __declspec(dllimport)
#  endif
#else
#  define DLP_API __attribute__((visibility("default")))
#endif

#define DLP_ABI_VERSION 1u

/* status codes */
#define DLP_OK                        0
#define DLP_ERR_INVALID_ARG           1   /* NULL pointer / bad length */
#define DLP_ERR_INVALID_INPUT         2   /* malformed JSON, invalid UTF-8, bad field value */
#define DLP_ERR_TOO_LARGE             3   /* text / batch above configured limits */
#define DLP_ERR_DETECTOR_UNAVAILABLE  4
#define DLP_ERR_TIMEOUT               5
#define DLP_ERR_RULES                 6   /* rule validation / compilation failed (old rules keep serving) */
#define DLP_ERR_STORAGE               7
#define DLP_ERR_POLICY                8
#define DLP_ERR_VAULT                 9
#define DLP_ERR_FORBIDDEN             10  /* permission / ownership check failed */
#define DLP_ERR_NOT_FOUND             11  /* unknown policy, unknown or expired vault session */
#define DLP_ERR_PANIC                 98  /* internal panic, isolated */
#define DLP_ERR_INTERNAL              99

typedef struct dlp_engine dlp_engine_t;
typedef struct dlp_stream dlp_stream_t;

typedef struct dlp_result {
    int         code;   /* same value as the function's return code */
    const char *data;   /* NUL-terminated UTF-8 JSON, owned by the library */
    size_t      len;    /* length of data in bytes, excluding the NUL */
    void       *_priv;  /* do not touch */
} dlp_result_t;

DLP_API uint32_t    dlp_abi_version(void);
DLP_API const char *dlp_version(void);

/* config_json (may be NULL/empty): {"db_path":"rules.db"|":memory:", "rules_dir":"rules",
 *   "nlp_url":"http://127.0.0.1:8791", "nlp_token":"", "use_hyperscan":true, "default_policy":"default",
 *   "max_text_bytes":4194304, "request_timeout_ms":30000, "vault_ttl_secs":3600, "nonce_placeholders":false}
 * On success *out_engine is set; *out_result carries the capabilities JSON (free it). */
DLP_API int  dlp_create(const char *config_json, size_t config_len, dlp_engine_t **out_engine, dlp_result_t **out_result);
DLP_API void dlp_destroy(dlp_engine_t *engine);

/* request: {"text":"...", "direction":"request|response|tool_input|tool_output", "language":"auto|zh|en",
 *           "policy_id":"default", "session_id":"...", "tenant_id":"...", "entities":[...], "detectors":[...]}
 * or, for chat payloads: {"payload":{...OpenAI/Anthropic JSON...}, "protocol":"openai.chat.completions", ...} */
DLP_API int dlp_detect   (const dlp_engine_t *e, const char *request_json, size_t request_len, dlp_result_t **out);
DLP_API int dlp_sanitize (const dlp_engine_t *e, const char *request_json, size_t request_len, dlp_result_t **out);
DLP_API int dlp_anonymize(const dlp_engine_t *e, const char *request_json, size_t request_len, dlp_result_t **out);

/* request: {"session_id":"...","text":"model reply with [PERSON_1]","tenant_id":"...","subject":"...",
 *           "direction":"response","policy_id":"default","check_response":true} */
DLP_API int dlp_deanonymize(const dlp_engine_t *e, const char *request_json, size_t request_len, dlp_result_t **out);

DLP_API int dlp_reload_rules(const dlp_engine_t *e, dlp_result_t **out);
DLP_API int dlp_capabilities(const dlp_engine_t *e, dlp_result_t **out);

DLP_API void dlp_free_result(dlp_result_t *r);

/* streaming (SSE) - options: {"policy_id","mode":"strict|window","anonymize":false,"session_id","tenant_id"}
 * push/finish results: {"output":"bytes to forward now","blocked":bool,"stats":{...}} */
DLP_API int  dlp_stream_open  (const dlp_engine_t *e, const char *options_json, size_t options_len, dlp_stream_t **out_stream, dlp_result_t **out);
DLP_API int  dlp_stream_push  (dlp_stream_t *s, const uint8_t *data, size_t len, dlp_result_t **out);
DLP_API int  dlp_stream_finish(dlp_stream_t *s, dlp_result_t **out);
DLP_API void dlp_stream_close (dlp_stream_t *s);

#ifdef __cplusplus
}
#endif
#endif /* AI_DLP_H */
