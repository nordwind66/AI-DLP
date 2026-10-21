# One-off, ONLINE: create the Python environment for the NLP service (pip install only; no models are downloaded).
#   .\scripts\windows\setup_nlp.ps1 -WorkDir D:\dlp-nlp
param([string]$WorkDir = "D:\dlp-nlp")
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
New-Item -ItemType Directory -Force $WorkDir | Out-Null
python -m venv "$WorkDir\venv"
$py = "$WorkDir\venv\Scripts\python.exe"
& $py -m pip install --upgrade pip
& $py -m pip install -r "$Root\services\nlp\requirements.txt"
Write-Host "done. Start with run_nlp.ps1 -WorkDir $WorkDir (runtime is fully offline, no models needed)"
