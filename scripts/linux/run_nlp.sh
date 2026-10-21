#!/usr/bin/env bash
# Start the NLP companion service (Presidio deterministic recognizers: regex + checksum + libphonenumber) on loopback.
# No models are needed or loaded. Fully offline at runtime.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${DLP_PYTHON:-python3}"
exec "$PY" -s -c "import sys; sys.path.insert(0, sys.argv[1]); import dlp_nlp.app as a; a.main()" "$ROOT/services/nlp"
