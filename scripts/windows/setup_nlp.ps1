# One-off, ONLINE: create the Python environment for the NLP service and download pinned models.
#   .\scripts\windows\setup_nlp.ps1 -WorkDir D:\dlp-nlp
param([string]$WorkDir = "D:\dlp-nlp")
$ErrorActionPreference = "Stop"
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
New-Item -ItemType Directory -Force $WorkDir | Out-Null
python -m venv "$WorkDir\venv"
$py = "$WorkDir\venv\Scripts\python.exe"
& $py -m pip install --upgrade pip
& $py -m pip install torch==2.5.1 --index-url https://download.pytorch.org/whl/cpu      # CPU-only wheel
& $py -m pip install -r "$Root\services\nlp\requirements.txt"
$env:DLP_MODELS_DIR = "$WorkDir\models"
& $py "$Root\scripts\fetch_models.py"            # pinned revisions, converts weights to safetensors, caches the tokenizer
Write-Host "done. Models in $WorkDir\models  (use run_nlp.ps1 -WorkDir $WorkDir; runtime is fully offline)"
