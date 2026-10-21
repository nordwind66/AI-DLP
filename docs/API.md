# HTTP API

Full machine-readable description: `docs/openapi.yaml` (also served at `GET /openapi.yaml`). Examples: `examples/python/http_client.py`,
`tests/api/test_api.py` (21 tests, run against a live server).

## Authentication, tenancy, scopes

`Authorization: Bearer <key>` (or `X-API-Key`). The server holds a JSON key table (`--api-keys`): `{id, key_sha256, tenant, subject,
scopes}`; keys are stored hashed, compared in constant time (`dlp-server genkey` prints a key once plus its hash). **Tenant,
subject and scopes come only from that table.** A `tenant_id` in a body is never trusted – if present and different → `403
tenant_mismatch`. `--insecure-no-auth` exists for loopback development only (refused on other addresses).

Scopes: `detect`, `sanitize`, `anonymize`, `deanonymize`, `deanonymize:skip_check`, `rules:reload` (reload, rollback, versions),
`metrics`, `debug:reveal` (`reveal_values`), `vault:admin` (cross-user vault access inside a tenant), `*`.

## Endpoints

| method path | scope | notes |
|---|---|---|
| POST `/v1/detect` | per `mode` | `mode`: detect (default) / sanitize / anonymize; `text` or structured `payload` |
| POST `/v1/sanitize` | sanitize | irreversible desensitization |
| POST `/v1/anonymize` | anonymize | reversible, tenant+session scoped vault; session id generated if absent (128-bit random) |
| POST `/v1/deanonymize` | deanonymize | restore after an independent response check; foreign/forged/unknown placeholders untouched |
| POST `/v1/detect/batch` | per item | ≤ 64 items; rules in parallel, one NLP round trip |
| POST `/v1/scan/stream` | sanitize/anonymize | SSE: whole stream (`text/event-stream`) or incremental JSON (`stream_id`, `chunk`, `final`) |
| POST `/v1/rules/reload` | rules:reload | validate → compile → atomic swap; failure keeps the old set (422) |
| POST `/v1/rules/rollback` | rules:reload | `{version}` |
| GET `/v1/rules/versions` | rules:reload | snapshots |
| GET `/v1/capabilities` | any key | detector states, ruleset, policies, limits, streaming-window availability, NLP status |
| GET `/health` | none | `ok` / `degraded` (an expected NLP detector is not ready) |
| GET `/metrics` | metrics | Prometheus text |

## Request fields

`text` | `payload`+`protocol`, `direction` (request/response/tool_input/tool_output), `language` (auto/zh/en), `policy_id`, `session_id`,
`tenant_id` (checked only), `mode`, `entities` (type filter), `detectors` (narrow; the policy's mandatory detectors are always kept),
`actions` (per entity-type override, **stricter than the policy only**), `nonce_placeholders`, `reveal_values` (debug scope).

## Response (text)

```json
{ "decision": "modified", "blocked_reason": null, "sanitized_text": "[REDACTED_PERSON]的手机号是138****8000。",
  "entities": [ { "entity_type": "PHONE_NUMBER", "start": 7, "end": 18, "byte_start": 7, "byte_end": 18, "confidence": 0.92,
                  "risk_level": "medium", "detector": "hyperscan", "rule_id": "cn-mobile", "action": "MASK", "applied_action": "MASK",
                  "context": "张三的手机号是[PHONE_NUMBER]。", "replacement": "138****8000", "metadata": {"evidence":"validated"} } ],
  "detector_status": [ {"name":"regex","state":"ready","enabled":true,"ran":true,"mandatory":true,"ms":0.4,"error":null}, … ],
  "degraded": false, "warnings": [], "actions": ["ANONYMIZE","MASK"], "policy_id": "default", "ruleset_version": 3,
  "session_id": null, "suppressed_low_confidence": 0, "processing_time_ms": 1.3 }
```

`start/end` are Unicode code points, `byte_*` are UTF-8 bytes. Values are never returned (contexts replace every detected span by
`[TYPE]` and blur long digit runs). `decision`: `allow` (nothing to act on), `modified` (something is, or in detect mode would be,
changed), `blocked` (only when a policy says BLOCK or a mandatory detector failed under `fail_closed`; `sanitized_text` is then null).

## Structured payloads

Send `payload` (+ optional `protocol`: `openai.chat.completions`, `openai.responses`, `anthropic.messages`, `json`; auto-detected).
Only text locations are read or written (message content, text parts, tool-call arguments, tool results, system prompts,
reasoning summaries). `role`, `model`, ids, `tool_call_id`, `tool_use_id`, `type`, `name`, `cache_control`, usage, `signature`, base64/data-URL
strings are structurally unreachable. Tool arguments given as a JSON string are parsed, edited at string leaves and re-serialized;
truncated/invalid arguments are sanitized as text. Integrity-protected blocks (`thinking` + `signature`, OpenAI `reasoning`) cannot be
edited: with `unmodifiable_action=drop` (default) the whole block is removed and reported in `unmodifiable_findings`/`warnings`;
`block` and `audit` are available. Identical texts (conversation history) are processed once; in anonymize mode all fields share
one vault session so equal values map to equal placeholders. Result adds `slots_scanned`, `slots_skipped`, `findings[pointer]`.

## Errors

`{"error":{"code","message"}}`; `message` is built from metadata only. 400 invalid_input, 401 unauthorized, 403 forbidden / tenant_mismatch,
404 not_found (policy; unknown, expired or foreign vault session – indistinguishable on purpose), 413 too_large, 422 rules_invalid /
policy_error, 503 detector_unavailable / overloaded (in-flight limit), 504 timeout.

## Limits and operation

`--max-text-bytes` (4 MiB), batch ≤ 64, `--request-timeout-secs` (30), `--nlp-max-bytes` (128 KiB sent to models), `--max-inflight` (256,
503 when exceeded), vault TTL (`--vault-ttl-secs`, 3600) with a 30 s sweeper, 1024 concurrent incremental streams, SSE event ≤ 1 MiB,
stream buffer ≤ max text. `--watch-rules-secs N` hot-reloads when the database changed (rejected reloads keep the old rules and
are logged). `--audit-log` prints one metadata-only JSON line per request (tenant, subject, policy, counts per entity type, decision,
degradation, timing – never text or values).
