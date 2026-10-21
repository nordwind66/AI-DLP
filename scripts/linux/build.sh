#!/usr/bin/env bash
# Build everything for Linux x86_64: server, CLI, shared library, C/C++ examples, native tests.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$ROOT"
cargo build --release --workspace
mkdir -p build/bin
cp target/release/{dlp,dlp-server,gitleaks-importer} build/bin/ 2>/dev/null || true
LIB=target/release
gcc -O2 -Wall -Iinclude examples/c/example.c    -L$LIB -lai_dlp -Wl,-rpath,'$ORIGIN/../../target/release' -o build/bin/example_c
g++ -O2 -Wall -std=c++17 -Iinclude examples/cpp/example.cpp -L$LIB -lai_dlp -Wl,-rpath,'$ORIGIN/../../target/release' -o build/bin/example_cpp
gcc -O1 -Wall -Iinclude tests/native/test_ffi.c -L$LIB -lai_dlp -lpthread -Wl,-rpath,"$ROOT/$LIB" -o build/bin/test_ffi
echo "built: $(ls build/bin | tr '\n' ' ')"
