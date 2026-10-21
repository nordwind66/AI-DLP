# Linux x86_64: build, run, test

Verified on Ubuntu 24.04 (kernel 6.18), 4 vCPU, 15 GB RAM, Rust 1.97, Python 3.13, gcc 13.

## 1. Prerequisites
```
apt-get install -y build-essential pkg-config cmake sqlite3 libhyperscan-dev   # libhyperscan-dev is optional (prefilter)
curl https://sh.rustup.rs | sh                                                 # Rust >= 1.80
```

## 2. Build everything
```
scripts/linux/build.sh      # cargo build --release --workspace + C/C++ examples + native test
```
Outputs in `build/bin/`: `dlp` (CLI), `dlp-server`, `gitleaks-importer`, `example_c`, `example_cpp`, `test_ffi`; the shared library is
`target/release/libai_dlp.so`; header `include/ai_dlp.h`.

## 3. NLP service (Presidio deterministic recognizers; optional)
Runs only Presidio's regex / checksum / libphonenumber recognizers (phone, email, credit card, IBAN, crypto, US ids) on a blank,
tokenizer-only spaCy pipeline. No ML models, no `models/` directory, starts in under a second. Person / organization / address
detection is NOT done here; it comes from the Rust rules and dictionaries.
```
python3 -m venv .venv && . .venv/bin/activate
pip install -r services/nlp/requirements.txt              # ONLINE, once; nothing else to download
DLP_PYTHON=$PWD/.venv/bin/python scripts/linux/run_nlp.sh   # OFFLINE at runtime, listens on 127.0.0.1:8791
```
Env: `DLP_NLP_CONCURRENCY` (2 parallel analyses), `DLP_NLP_QUEUE` (32, 503 beyond), `DLP_NLP_MAX_CHARS`, `DLP_NLP_TOKEN` (shared
secret), `DLP_NLP_HOST`, `DLP_NLP_PORT`, `DLP_PRESIDIO=0` (disable the recognizers).

## 4. Initialise the rule database and start the server
```
build/bin/dlp --db ai_dlp.db --rules-dir rules init           # imports 222 gitleaks rules + built-in rules + policies
build/bin/dlp-server genkey                                    # prints a key once + its sha256
cat > keys.json <<'J'
[{"id":"gw","key_sha256":"<hash>","tenant":"acme","subject":"gateway","scopes":["detect","sanitize","anonymize","deanonymize"]},
 {"id":"ops","key_sha256":"<hash2>","tenant":"acme","subject":"ops","scopes":["rules:reload","metrics"]}]
J
build/bin/dlp-server --db ai_dlp.db --rules-dir rules --api-keys keys.json --nlp-url http://127.0.0.1:8791 --watch-rules-secs 30 --audit-log
```
CLI quick look: `build/bin/dlp --db ai_dlp.db detect -m sanitize -t '张三的手机号是13800138000。'`
(`--nlp-url` adds the Presidio recognizers; raw values are never printed unless `--reveal`).

## 5. Tests
```
scripts/prepare_test_data.sh --gitleaks     # generated test data (accuracy set; gitleaks oracle needs Go ≥ 1.24 + network once)
cargo test --workspace                       # unit + engine/protocol/stream/parity/consistency tests (≈ 4 min in the dev profile)
scripts/linux/build.sh && build/bin/test_ffi # native ABI test
scripts/linux/run_api_tests.sh               # 21 HTTP API tests (set DLP_NLP_URL=… to include the Presidio tests)
python -m pytest services/nlp/tests          # NLP service tests
python benchmarks/accuracy/eval.py           # accuracy (needs server + NLP running, see docs/ACCURACY_REPORT.md)
bash scripts/gen_gitleaks_expected.sh        # regenerate the gitleaks oracle (needs Go ≥ 1.24, network once)
```

## 6. Production notes
Run server and NLP service as separate systemd units under an unprivileged user; bind both to loopback (or a unix-domain proxy) and
put TLS in front; keep `keys.json` and the SQLite file readable only by the service user; set `DLP_NLP_TOKEN`; scrape `/metrics`;
ship `--audit-log` lines (metadata only). The NLP service is light (regex/checksum only); `DLP_NLP_CONCURRENCY` ≤ cores is plenty. The vault is
in memory only (restart = sessions lost; nothing sensitive is written to disk).
