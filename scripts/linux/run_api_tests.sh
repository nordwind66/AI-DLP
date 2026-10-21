#!/usr/bin/env bash
# Starts a throw-away dlp-server (rules only unless DLP_NLP_URL is set), runs tests/api, stops it.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$ROOT"
mkdir -p build/run
if [ ! -f build/run/keys.json ]; then
  A=$(./target/release/dlp-server genkey); U=$(./target/release/dlp-server genkey)
  echo "$A" | sed -n 's/API key (shown once): //p' > build/run/admin.key; echo "$U" | sed -n 's/API key (shown once): //p' > build/run/user.key
  cat > build/run/keys.json <<J
[{"id":"admin","key_sha256":"$(echo "$A" | sed -n 's/key_sha256: //p')","tenant":"acme","subject":"ops","scopes":["detect","sanitize","anonymize","deanonymize","rules:reload","metrics","admin","debug:reveal"]},
 {"id":"app","key_sha256":"$(echo "$U" | sed -n 's/key_sha256: //p')","tenant":"acme","subject":"chat-app","scopes":["detect","sanitize","anonymize","deanonymize"]}]
J
fi
PORT="${DLP_TEST_PORT:-18080}"; rm -f build/run/apitest.db*
./target/release/dlp-server --listen 127.0.0.1:$PORT --db build/run/apitest.db --api-keys build/run/keys.json ${DLP_NLP_URL:+--nlp-url $DLP_NLP_URL} >build/run/apitest.log 2>&1 &
PID=$!; trap 'kill $PID 2>/dev/null || true' EXIT
for i in $(seq 1 50); do curl -s localhost:$PORT/health >/dev/null 2>&1 && break; sleep 0.2; done
DLP_URL=http://127.0.0.1:$PORT python3 tests/api/test_api.py -v
