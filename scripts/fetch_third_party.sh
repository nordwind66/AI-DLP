#!/usr/bin/env bash
# Re-create third_party/ at the pinned commits (source study, parity tests). Not needed to RUN the engine.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; mkdir -p "$ROOT/third_party"; cd "$ROOT/third_party"
get() { # name repo commit
  if [ ! -d "$1/.git" ]; then git init -q "$1" && git -C "$1" remote add origin "$2"; fi
  git -C "$1" fetch -q --depth 1 origin "$3" && git -C "$1" checkout -q FETCH_HEAD
  echo "$1 @ $(git -C "$1" rev-parse HEAD)"
}
get presidio  https://github.com/data-privacy-stack/presidio 4f0e236e31a57767958a3eec2de3fc58dffc3034
get llm-guard https://github.com/protectai/llm-guard        168c1034ffdb33837e7ae6fd6a16b80567c1be03
get gitleaks  https://github.com/gitleaks/gitleaks          b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b
