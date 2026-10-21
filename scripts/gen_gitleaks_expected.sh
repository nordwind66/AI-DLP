#!/usr/bin/env bash
# Regenerates tests/data/gitleaks_{corpus,expected}.json from the pinned upstream gitleaks source.
# Requires Go >= 1.24 and network access to the Go module proxy (first run only).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$ROOT/build/gitleaks_work"
rm -rf "$WORK" && mkdir -p "$ROOT/build/bin" && cp -r "$ROOT/third_party/gitleaks" "$WORK"
python3 "$ROOT/scripts/patch_gitleaks_dump.py" "$WORK"        # adds corpus dump hook + difftool
( cd "$WORK/cmd/generate/config" && rm -f "$ROOT/build/corpus_raw.jsonl" && GL_CORPUS="$ROOT/build/corpus_raw.jsonl" go run . "$WORK/config/regenerated.toml" )
( cd "$WORK" && CGO_ENABLED=0 GOFLAGS=-mod=mod go build -o "$ROOT/build/bin/gl_difftool" ./cmd/difftool )
python3 "$ROOT/scripts/build_gitleaks_corpus.py" "$ROOT"
"$ROOT/build/bin/gl_difftool" < "$ROOT/build/samples.json" > "$ROOT/tests/data/gitleaks_expected.json"
echo "done"
