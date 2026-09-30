# Full local run. 5s interval, STALE after 12s. No Maven/Gradle needed.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
javac -d out (Get-ChildItem -Recurse java/src/*.java)
if (!(Test-Path "config/baseline.json")) {
  java -cp out integrity.enroll.Enroller "java/src/integrity/agent/AgentState.java" "config/agent-config.json"
}
java -cp out integrity.Main
