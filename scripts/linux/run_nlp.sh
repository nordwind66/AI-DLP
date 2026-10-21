#!/usr/bin/env bash
# Start the NLP companion service (Presidio + GLiNER) on loopback. Models must already be in ./models
# (python scripts/fetch_models.py). Fully offline at runtime.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${DLP_PYTHON:-python3}"
exec "$PY" -s -c "import sys; sys.path.insert(0, sys.argv[1]); import dlp_nlp.app as a; a.main()" "$ROOT/services/nlp"
