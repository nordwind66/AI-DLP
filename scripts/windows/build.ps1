# Build the Unified AI DLP Engine on Windows x64 (MSVC toolchain).
#   .\scripts\windows\build.ps1 [-WorkDir D:\dlp-build]
# Prerequisites: Rust (rustup, stable-x86_64-pc-windows-msvc), Visual Studio Build Tools (C++), Python 3.10-3.13 for the NLP service.
# Large artefacts (cargo target dir, models, venv) go to -WorkDir, NOT to the system drive.
param([string]$WorkDir = "")
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
if ($WorkDir -ne "") { $env:CARGO_TARGET_DIR = Join-Path $WorkDir "target" }
$Target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $Root "target" }
Push-Location $Root
cargo build --release --workspace
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
$Out = Join-Path $Root "build\bin"; New-Item -ItemType Directory -Force $Out | Out-Null
$Rel = Join-Path $Target "release"
Copy-Item "$Rel\dlp.exe","$Rel\dlp-server.exe","$Rel\gitleaks-importer.exe","$Rel\ai_dlp.dll","$Rel\ai_dlp.dll.lib" $Out -Force
# C / C++ examples + native test (run from a "x64 Native Tools Command Prompt" so cl.exe is on PATH)
if (Get-Command cl.exe -ErrorAction SilentlyContinue) {
  cl /nologo /W3 /I include examples\c\example.c "$Out\ai_dlp.dll.lib" /Fe:"$Out\example_c.exe" /Fo:"$Out\"
  cl /nologo /W3 /EHsc /std:c++17 /I include examples\cpp\example.cpp "$Out\ai_dlp.dll.lib" /Fe:"$Out\example_cpp.exe" /Fo:"$Out\"
} else { Write-Warning "cl.exe not found: skipping the C/C++ examples (open an x64 Native Tools prompt)" }
Pop-Location
Write-Host "built into $Out"
Write-Host "NOTE: Hyperscan is not available on Windows by default -> the portable regex backend is used (results are identical, see docs/ARCHITECTURE.md). Put hs.dll next to dlp-server.exe or set DLP_HYPERSCAN_LIB to enable the prefilter."
