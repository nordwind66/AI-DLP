# Gitleaks parity

## Method

`scripts/gen_gitleaks_expected.sh` copies the pinned gitleaks source (`b58d3f1`) to `build/`, patches the **copy** so that
`cmd/generate/config/utils.Validate` dumps every rule's true-/false-positive samples (the samples gitleaks itself uses to test
its rules; 6368 TP + 342 FP, 6289 unique strings; random per generation). The files are **generated, not committed**
(`scripts/prepare_test_data.sh --gitleaks`): they contain key-shaped strings that public-repo secret scanning rightly flags, builds `tools/gitleaks-parity/difftool.go` against the real `detect` package, and records
what upstream reports for each sample (default config, decoding disabled). `crates/dlp-storage/tests/gitleaks_parity.rs`
imports `rules/gitleaks.toml` into SQLite, compiles it (with Hyperscan on), runs `SecretDetector` on every sample and compares
the set of `(rule_id, secret)` per sample.

**Result: 6289 / 6289 identical.** (Upstream itself detects 5934/5958 of its own TPs: allowlists/stopwords legitimately suppress
a few synthetic values; we reproduce exactly that.)

## Semantics reproduced (gitleaks → this repo)

| gitleaks | here |
|---|---|
| `detect.go: DetectContext` keyword prefilter (lower-cased text, Aho-Corasick) | `RuleSet::scan` step 1 (ASCII-case-insensitive AC over all keywords) |
| `detectRule` regex `FindAllStringIndex`, `strings.Trim(match,"\n")` | `run_rule` |
| secret = `r.Regex.FindStringSubmatch(match)` (re-match on the matched substring), `secretGroup`, first non-empty group when unset | same, including re-matching on the substring (anchors behave as upstream) |
| entropy: Shannon over runes, divided by **byte** length, skip if `entropy <= rule.entropy` | `validators::shannon_entropy`, same comparison |
| `checkFindingAllowed`: global then rule allowlists; OR = regex‖stopword, AND = all present criteria; `regexTarget` secret/match/line; stop-words match lower-cased secret substring; paths/commits never satisfied in text mode | `CompiledAllowlist::allows` |
| `processRequiredRules`, `withinLines/withinColumns` | `apply_required` |
| `filter()`: drop a *generic* finding if a non-generic rule on the same line found a secret containing it | `RuleSet::filter_generic` (this alone explained 4422 of the first run's differences) |
| `Rule.Validate`: secretGroup ≤ groups, allowlist non-empty | `RuleSet::compile` |
| `gitleaks:allow` inline comment | **deliberately not honoured** (an attacker controls the text; `ScanOptions.honor_inline_allow` exists but is off) |
| decoding passes (base64/hex/percent/unicode, depth 5) | **not implemented** – see KNOWN_ISSUES |

## Dialect differences found by importing the real rules

Go `regexp` and Rust `regex` are both linear-time but not equivalent. `crates/dlp-rules/src/compat.rs` translates; all 221 content rules compile:

* `\w \d \s \b` are ASCII-only in Go, Unicode-aware in Rust → rewritten to explicit ASCII classes / `(?-u:\b)` (182 of 222 rules touched).
* `{` that is not a valid quantifier is a literal in Go (`${…}`, `{[0-9]+}` in the global allowlist) and an error in Rust → escaped.
* `\Q…\E` expanded; `\Z`/`\C` rejected; a literal `[` inside a class escaped; `&& -- ~~` inside classes escaped; `-` after a shorthand
  inside a class made literal; negated shorthand inside a class (`[\S\s-]` in `private-key`) → nested ASCII class.
* Compile limits (size/nesting) bound memory for hostile rules; no backtracking engine exists, so ReDoS is structurally impossible.

Anything the translator cannot represent is imported disabled with the reason (`compat='unsupported'`) – currently none.
