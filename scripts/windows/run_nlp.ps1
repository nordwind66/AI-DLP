# Start the NLP service (Presidio + GLiNER, CPU, offline) on 127.0.0.1:8791.
param([string]$WorkDir = "D:\dlp-nlp", [int]$Port = 8791)
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
$env:DLP_MODELS_DIR = "$WorkDir\models"
$env:HF_HOME = "$WorkDir\models\hf_home"; $env:HF_HUB_OFFLINE = "1"; $env:TRANSFORMERS_OFFLINE = "1"
$env:DLP_NLP_PORT = "$Port"
& "$WorkDir\venv\Scripts\python.exe" -s -c "import sys; sys.path.insert(0, sys.argv[1]); import dlp_nlp.app as a; a.main()" "$Root\services\nlp"
