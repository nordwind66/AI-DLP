# Start the NLP service (Presidio deterministic recognizers, CPU, offline, no models) on 127.0.0.1:8791.
param([string]$WorkDir = "D:\dlp-nlp", [int]$Port = 8791)
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
$env:DLP_NLP_PORT = "$Port"
& "$WorkDir\venv\Scripts\python.exe" -s -c "import sys; sys.path.insert(0, sys.argv[1]); import dlp_nlp.app as a; a.main()" "$Root\services\nlp"
