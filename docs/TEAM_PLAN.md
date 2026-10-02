# Team Plan — Checker / Ledger / Verifier / Tester (rebalanced)

## Roles (no one idle, integration frozen in first 20 min)
- **Checker:** `Measurer`, `AgentState`, `Signer`, `KeyStore`, `Enroller`, `SeqStore`. Owns frozen payload + canonical hashing + key files.
- **Ledger:** `ChainAnchor`, `contract/contracts/Integrity.sol`, `batch/*`, `scripts/redeploy`. Owns event log, Merkle batch, fallback file, redeploy script.
- **Verifier:** `Verifier`, `ui/Dashboard`, watchdog, verdict codes. Owns 4-family checks + STALE + per-component blame + UI.
- **Tester:** `batch/Bench20`, `batch/BatchBench`, tamper scripts, `docs/BENCHMARKS.md`, PPT. Owns 20-trial numbers + demo script + trap checklist.

## Frozen interfaces (do not change after minute 20)
- Signed payload: `agentId|seq|ts|hBin|hCfg|hMem|hComb|prevHash` (UTF-8 pipe).
- JSON: `{agentId,seq,ts,hBin,hCfg,hMem,hComb,prevHash,sig,ledgerRef}`.
- REST: `GET /` dashboard, `GET /tamper/memory?limit=`, `GET /tamper/memory/clear`.
- Timing: 5s interval, STALE after 12s. Numbers in `docs/BENCHMARKS.md`.

## Setup traps checklist (run before 12:00 PM)
- [ ] No Jackson: canonicalization is manual TreeMap (item 15 — SORT_KEYS trap avoided by design).
- [ ] Events use `bytes32 indexed agentIdHash` + plain `string agentId` (item 16).
- [ ] Loop wrapped try/catch, fixed-delay sleep (item 17).
- [ ] Binary tamper: config is main demo; JAR locked on Windows — test binary tamper on Linux/macOS or stopped agent (item 18).
- [ ] No web3j wrapper: plain HttpClient probe; redeploy after Anvil restart; build `out/` once now, keep cache (item 19).
- [ ] File reads retry 200ms; missing file = tamper (item 20).
- [ ] Stack is JDK-only (neither Maven/Spring nor Gradle/Javalin needed for MVP). Build with `javac`, run with `java`.
