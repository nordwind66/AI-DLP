# Architecture

## 1. What it is

A standalone engine that finds sensitive data in LLM prompts and responses and **desensitizes** it (mask / redact /
replace / reversible anonymize). Blocking exists but is an explicit opt-in action; every built-in policy except
`block-secrets` sanitizes and forwards. It combines three open-source projects at the level where each is strongest. No statistical / ML model (GLiNER, spaCy NER, transformers) is used anywhere: every detector is deterministic (regex, checksum, dictionary, entropy):

| Concern | Taken from | How it is used |
|---|---|---|
| Deterministic PII recognizers: phone (libphonenumber), email, credit card, IBAN, crypto, US ids | Microsoft Presidio (`presidio-analyzer 2.2.364`) | runs as a **detector** in the Python NLP service, on a blank tokenizer-only spaCy pipeline; Presidio's NER (`SpacyRecognizer`) is removed, so it never produces PERSON / LOCATION / ORGANIZATION |
| Credential rules and detection algorithm | Gitleaks (`b58d3f1`) | 222 rules imported into SQLite; algorithm re-implemented in Rust (`dlp-rules`) |
| Reversible anonymization design for LLMs | LLM Guard (`168c103`, archived) | placeholder scheme / conflict handling ported to Rust; Vault redesigned (docs/RESEARCH.md §2) |

Not used at runtime: `presidio-anonymizer`, `llm-guard`, the gitleaks binary (the binary is built only as the oracle for the
parity test). Reasons are in §6.

## 2. Process / library layout

```
 host app ──C ABI──►  libai_dlp.so / ai_dlp.dll ┐
 gateway  ──HTTP──►   dlp-server (axum)         ├─► dlp-engine ──► rule detectors (in-process, Rust)
 operator ──CLI───►   dlp                       ┘        │             regex / hyperscan / secret / dictionary
                                                         │
                                                         └──► NlpClient ──HTTP/loopback, keep-alive──► services/nlp (Python)
                                                                                                          └ Presidio (deterministic recognizers:
                                                                                                            regex + checksum + libphonenumber)
```

* The Rust core is complete and useful **without** the NLP service: rules, secrets, dictionaries, policy, vault, protocol
  and stream handling all live in the library. The DLL alone does **not** contain Presidio; with `nlp_url`
  configured it calls the NLP service, and when that is unreachable every response says so (`degraded:true`,
  per-detector `error`) – never "no sensitive data found".
* The NLP service is a separate long-running process. It loads no models (blank tokenizer-only spaCy pipeline plus
  Presidio's deterministic recognizers), starts in under a second and needs no `models/` directory. It is *not* spawned per
  text. Rust talks to it over a pooled loopback HTTP connection (`/v1/analyze` with `detectors:["presidio"]`), so a text is
  serialized once and analysed in parallel with the Rust rule scan.
* Person / organization / address detection is not done by the service; it is rule-based in Rust (labelled and possessive
  name patterns, dictionaries, province-anchored addresses). See docs/KNOWN_ISSUES.md.
* No GPU is needed or used. Detectors are: `regex`, `hyperscan`, `secret`, `dictionary`, `presidio`.

### Crates

| crate | role |
|---|---|
| `dlp-core` | `Entity`, `Detector` trait, UTF-8 byte ↔ code-point offsets, multi-detector merge |
| `dlp-rules` | Go→Rust regex dialect translation, validators, gitleaks-semantics `RuleSet`, Hyperscan dlopen prefilter, rule detectors |
| `dlp-storage` | SQLite schema/migrations, versions/rollback, audit triggers, gitleaks + built-in importers |
| `dlp-policy` | policy model and per-entity decision (`rule_id > entity_type > category > risk > default`) |
| `dlp-anonymizer` | masking, the single-pass executor, session-scoped Token Vault |
| `dlp-detectors` | NLP client (circuit breaker, deadlines) + Presidio detector |
| `dlp-protocol` | OpenAI chat / OpenAI responses / Anthropic / generic JSON text-slot extraction and write-back |
| `dlp-stream` | SSE parser, format adapters, strict and window stream scanners |
| `dlp-engine` | facade: pipeline, failure modes, reload/rollback, protocol scan, stream adapter, JSON request schema |
| `dlp-ffi` | C ABI (`ai_dlp.h`) |
| `apps/dlp-server`, `apps/dlp-cli`, `tools/gitleaks-importer` | REST API, CLI, rule importer |

(Deviation from the suggested layout: `RegexDetector`/`HyperscanDetector`/`SecretDetector`/`DictionaryDetector` live in
`dlp-rules` because they are thin wrappers over one hot-swappable `RuleSet`; `dlp-detectors` holds the NLP detectors.)

## 3. The pipeline (one text)

```
validate (size, UTF-8, scope, policy)
 → shield vault placeholders issued by this session           (so "[PERSON_1]" is never re-detected)
 → [parallel] rule detectors (regex|hyperscan, secret, dictionary)   ‖   NLP call (Presidio, one round trip, gated)
 → merge:  fuse identical spans, union same-type overlaps, resolve cross-type overlaps by
           (evidence ▸ rule priority ▸ risk ▸ confidence ▸ length), trim losing weaker-evidence spans
 → LLM-Guard step: merge same-type names split by spaces
 → policy: per entity action + confidence threshold (low-confidence entities are suppressed and counted)
 → ONE executor pass over the original text (mask / redact / replace / anonymize→vault)  [only place text changes]
 → response: entities (offsets, never values), sanitized_text, detector_status, degraded, warnings, timing, audit event
```

Detectors only *report* `Entity` (byte offsets, type, confidence, risk, detector, rule_id, action, masked context,
metadata). No detector rewrites text, so offsets can never drift.

### Merging (why not an average)

Evidence classes: `Validated` (checksum/format/fixed-prefix/entropy rule) > `Pattern` > `Model`. `Evidence::Model` still
exists in the enum (and the merge logic for it is kept and unit-tested) but nothing produces it by default, since no model
detector ships; in practice only `Validated` and `Pattern` evidence occurs. Confidence of the same entity from independent
families is combined with a capped noisy-OR (`Validated` + corroborating detector → +0.05 max), never averaged. A losing
lower-evidence span that only partly overlaps a winner keeps its larger remaining side (≥ 4 bytes). Same-type adjacent names
separated by spaces are merged (`merge_adjacent_same_type`, port of LLM Guard).

### Offsets

Native = UTF-8 byte offsets. The API layer converts once with `OffsetMap`; responses carry code-point `start/end` and raw
`byte_start/byte_end`. Python NLP results arrive as code points and are converted to bytes in one linear pass.
Tested with emoji, CJK, mixed text and overlaps.

## 4. Failure handling

* Policy `fail_mode`: `fail_closed` or `fail_open_with_audit`; `mandatory_detectors` lists detectors whose failure is governed
  by it. A mandatory detector failing under `fail_closed` → `decision: blocked`, reason names the detector (this is the only
  automatic way to get a block). Non-mandatory failures proceed with `degraded:true` + warning + audit event.
* NLP: per-call deadline, concurrency gate with bounded queue (`nlp_max_inflight`, back-pressure → degraded, not unbounded
  latency), circuit breaker after 3 consecutive failures, service-side 503 when its own queue is full. Texts above
  `nlp_max_bytes` (128 KiB) are not sent to the NLP service (reported as that detector failing). The built-in `strict` policy
  has `mandatory_detectors = [secret, regex, presidio]`.
* Detector panics are caught and isolated per detector; the C ABI never unwinds.
* Rule reload: compile everything; any enabled rule failing → the old rule set keeps serving. Hyperscan rejecting a pattern
  only moves that pattern to the exact-regex path.

## 5. Rules in SQLite, hot reload

All rules, validators, allowlists, dictionaries and policies live in SQLite (docs/DATABASE.md). `reload_rules()` reads one
consistent snapshot, validates + compiles, snapshots it into `rule_versions` (content-addressed), then swaps an
`Arc<RuleSet>` through `ArcSwap`. In-flight requests keep their old `Arc`; new ones see the new set. Rollback restores a
snapshot into the tables and runs the same validated path; if the restored set does not compile the tables are put back.
Triggers audit every rule edit made by *any* client (including the sqlite3 shell).

## 6. Decisions and deviations (with evidence)

1. **Gitleaks is re-implemented, not shelled out.** A faithful port needs the Go→Rust dialect translation (ASCII `\w \d \s \b`,
   literal `{`, `\Q..\E`, negated shorthand in classes: all found by importing the real 222 rules) plus keyword prefilter,
   secretGroup extraction (re-match on the substring, like upstream), entropy (`<=`, byte-length normalisation), allowlists
   (OR/AND, regexTarget secret/match/line, stopwords), `required` rules and the post-filter that drops *generic* findings when
   a specific rule found the same secret. Verified against the real binary: **6289/6289 samples identical**
   (docs/GITLEAKS_PARITY.md).
2. **Hyperscan is a prefilter only**, loaded with `dlopen` (`libhs.so.5` / `hs.dll`), compiled with `PREFILTER|SINGLEMATCH|UTF8`.
   Candidates are re-verified with the exact regex, so it cannot change results; verified on 2177 texts / 2068 entities,
   identical with and without it. It covers only keyword-less rules: a few keyword-gated gitleaks rules need seconds in the
   Hyperscan compiler (`kubernetes-secret-yaml`: 8.6 s) and already have gitleaks' own Aho-Corasick prefilter. Windows has no
   libhs by default → the portable path is used and reported (`backend=regex`).
3. **Presidio Anonymizer is not used at runtime.** The projects must not each rewrite the text, so every detector returns
   entities and one Rust executor applies actions. Presidio's operator semantics (replace/mask/redact) are mirrored in
   `dlp-anonymizer/src/mask.rs`.
4. **LLM Guard is archived and unsafe as-is for a multi-tenant gateway**: its Vault is a global list, `Deanonymize` offers
   fuzzy/case-insensitive modes (`REDACTED_PERSON_9`, which was never issued, is restored to a real name – reproduced in
   docs/m1_llmguard_verify.txt) and chained `str.replace` (a restored value containing another placeholder is expanded again).
   Ported: placeholder scheme, same value → same placeholder, conflict/union resolution, whitespace merge. Replaced: Vault.
5. **No model-based detection, by product decision.** GLiNER and every other statistical / ML detector (spaCy NER, transformers,
   ONNX) were evaluated during research (docs/RESEARCH.md) and then removed: the requirement is deterministic, auditable,
   model-free detection that loads instantly and ships no weights. Deterministic rules with validators carry structured data;
   contextual rules (`cn-name-labeled`, `cn-name-possessive`) and dictionaries carry person/organization cases; addresses use
   the province-anchored `cn-address` rule. The cost is recall: unlabelled names and free-form company names are missed
   (docs/KNOWN_ISSUES.md #1).
6. **Desensitize, don't refuse.** Private keys are replaced by `[REDACTED_PRIVATE_KEY]` (also when a pasted key has no END
   marker), integrity-protected blocks that contain sensitive data (`thinking`+`signature`, OpenAI `reasoning`) are removed as a
   whole instead of failing the request, and streams keep flowing with the sensitive parts replaced.
