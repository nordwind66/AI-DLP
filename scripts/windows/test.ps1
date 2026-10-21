# Run the Rust test-suite and the CLI smoke test on Windows.
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path; Push-Location $Root
cargo test --workspace
$env:DLP_DB = "build\smoke.db"; Remove-Item build\smoke.db* -ErrorAction SilentlyContinue
.\build\bin\dlp.exe init
.\build\bin\dlp.exe detect -m sanitize --detectors regex,secret -f tests\data\smoke_utf8.txt
Pop-Location
