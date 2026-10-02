# STALE demo: stalls the heartbeat by exclusively locking the config file.
# Engine must be running. Watch :8080: GREEN -> RED CYCLE_ERR -> STALE (~12s)
# -> GREEN again after the lock releases. No process kill needed, so the
# dashboard keeps serving (single-process demo: killing the JVM would take the
# dashboard down too and just show "engine unreachable").
param([int]$Seconds = 20)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$cfg = Join-Path $root "config/agent-config.json"

$fs = [IO.File]::Open((Resolve-Path $cfg), 'Open', 'ReadWrite', 'None')
try {
  Write-Host "Config locked for $Seconds seconds (simulated hung checker)."
  Write-Host "Watch http://localhost:8080 : RED CYCLE_ERR first, STALE after 12s."
  Start-Sleep $Seconds
} finally {
  $fs.Close()
}
Write-Host "Lock released. Next 5s heartbeat recovers to GREEN."
