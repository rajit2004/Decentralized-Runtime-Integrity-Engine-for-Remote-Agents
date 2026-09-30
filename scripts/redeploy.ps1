# Redeploy after Anvil restart (chain wipes on restart). Run in order.
# 1) npx hardhat node (terminal 1)  2) this script (terminal 2)  3) engine (terminal 3)
# Build out/ once now and keep the cache — first Gradle/npm run needs wifi.
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Push-Location "$PSScriptRoot/../contract"
try {
  if (!(Test-Path "node_modules")) { npm install }
  npx hardhat run scripts/deploy.js --network localhost
} finally { Pop-Location }
Write-Host "Save printed address into docs / config. Engine uses :8545 probe + ledger.jsonl fallback."
