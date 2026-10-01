# Demo tamper script. Engine must already be running (scripts/run.ps1 + :8080 GREEN).
# Config attack (main demo on Windows: JAR locked / classes dir, so config is primary).
# Memory attack needs no file edit: curl http://localhost:8080/tamper/memory?limit=999
Set-StrictMode -Version Latest
$cfg = Join-Path (Split-Path $PSScriptRoot -Parent) "config/agent-config.json"
$bak = "$cfg.demo-bak"
Copy-Item $cfg $bak -Force
try {
  $c = [IO.File]::ReadAllText($cfg)
  [IO.File]::WriteAllText($cfg, ($c -replace '"threshold": 100', '"threshold": 999'))
  Write-Host "Tampered. Watch :8080 flip RED POLICY_CFG_CHANGED comp=config within one 5s interval."
  Start-Sleep 8
} finally {
  Copy-Item $bak $cfg -Force
  Remove-Item $bak -Force -ErrorAction SilentlyContinue
  Write-Host "Restored. Re-enroll only if source/config bytes changed: java -cp out integrity.enroll.Enroller ..."
}
