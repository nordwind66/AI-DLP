#!/usr/bin/env bash
# Generate the test data that is intentionally NOT committed (it contains synthetic, key-shaped strings).
#   accuracy dataset  : always (deterministic, fixed seed)           -> tests/data/accuracy/dataset.jsonl
#   gitleaks oracle   : with --gitleaks (needs Go >= 1.24 + network)  -> tests/data/gitleaks_{corpus,expected}.json
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
python3 tests/data/accuracy/build_dataset.py
if [ "${1:-}" = "--gitleaks" ]; then
  [ -d third_party/gitleaks ] || scripts/fetch_third_party.sh
  bash scripts/gen_gitleaks_expected.sh
fi
