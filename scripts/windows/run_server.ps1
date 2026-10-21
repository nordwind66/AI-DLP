# Start dlp-server. Create keys first:  .\build\bin\dlp-server.exe genkey   (put the printed hash into keys.json)
param([string]$Keys = "keys.json", [string]$Db = "ai_dlp.db", [string]$Nlp = "http://127.0.0.1:8791", [string]$Listen = "127.0.0.1:8080")
$Root = (Resolve-Path "$PSScriptRoot\..\..").Path
& "$Root\build\bin\dlp.exe" --db $Db --rules-dir "$Root\rules" init
& "$Root\build\bin\dlp-server.exe" --listen $Listen --db $Db --rules-dir "$Root\rules" --api-keys $Keys --nlp-url $Nlp --watch-rules-secs 30 --audit-log
