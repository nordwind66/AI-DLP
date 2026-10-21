# Windows x64: build, run, test

## What was verified and what was not

| item | status |
|---|---|
| Cross-compiled `x86_64-pc-windows-gnu` (mingw-w64) workspace: `dlp.exe`, `dlp-server.exe`, `gitleaks-importer.exe`, `ai_dlp.dll` (+import lib) | **built** (Ubuntu host) |
| Executing those binaries (Wine 9): `dlp init` (imports 222 + 35 rules into SQLite), `dlp detect` with BOM-prefixed UTF-8 input, no `hs.dll` → portable backend | **ran, results identical to Linux** |
| Hyperscan-vs-portable consistency over 2177 texts / 2068 entities (the Windows path *is* the portable path) | **test passes** (`backend_consistency.rs`) |
| MSVC (`x86_64-pc-windows-msvc`) build, `build.ps1`, `cl.exe` C/C++ examples, PowerShell scripts, the Python NLP service on Windows | **not run here** (no Windows machine); written to the same commands and the code is portable (no `unix`-only APIs outside `cfg`) |

## Build (PowerShell, MSVC toolchain)
```
winget install Rustlang.Rustup ; rustup default stable-x86_64-pc-windows-msvc        # + "Desktop development with C++" Build Tools
.\scripts\windows\build.ps1 -WorkDir D:\dlp-build          # target dir on D:, not the system drive
```
Result in `build\bin\`: `dlp.exe`, `dlp-server.exe`, `gitleaks-importer.exe`, `ai_dlp.dll`, `ai_dlp.dll.lib`, examples (from an x64 Native Tools prompt).
Link your own app with `include\ai_dlp.h` + `ai_dlp.dll.lib`; ship `ai_dlp.dll` next to it. No CRT redistributable beyond the default is needed for the MSVC build.

Hyperscan: there is no official Windows build. `libloading` tries `hs.dll`/`libhs.dll`/`vectorscan.dll` (or `DLP_HYPERSCAN_LIB`) and otherwise
silently uses the portable engine – `GET /v1/capabilities` shows `hyperscan_active:false`. Results are the same (it is only a prefilter).

## NLP service
```
.\scripts\windows\setup_nlp.ps1 -WorkDir D:\dlp-nlp        # ONLINE once: venv + pip install -r services\nlp\requirements.txt (no models)
.\scripts\windows\run_nlp.ps1   -WorkDir D:\dlp-nlp        # offline afterwards
.\scripts\windows\run_server.ps1 -Keys keys.json           # init DB + start API on 127.0.0.1:8080
```
Command-line arguments with non-ASCII text work natively on Windows; for scripts prefer `-f file.txt` (UTF-8, BOM accepted) or stdin.

## Tests
`.\scripts\windows\test.ps1` (cargo tests + CLI smoke). The HTTP API suite runs unchanged against a Windows server:
`$env:DLP_URL="http://127.0.0.1:8080"; $env:DLP_KEY_USER=…; $env:DLP_KEY_ADMIN=…; python tests\api\test_api.py`.
