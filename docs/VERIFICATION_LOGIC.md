# Verification Logic - Frozen Shared Contract (v2)

## Frozen wire (first 20 min, no changes after)
Signed payload (UTF-8, pipe-separated):
`agentId|seq|ts|hBin|hCfg|hMem|hComb|prevHash`

Measurement JSON (Checker -> Verifier / ledger / dashboard):
`{"agentId","seq","ts","hBin","hCfg","hMem","hComb","prevHash","sig","ledgerRef"}`

Rules everyone shares:
- Hashes 64-char lowercase hex.
- `hComb = SHA256(raw32(hBin) || raw32(hCfg) || raw32(hMem))`, NOT hex strings.
- `ts` Unix seconds. `seq` starts 1 (0 = genesis baseline).
- `prevHash` = previous `hComb`. Genesis prev = 64 zeros or baseline `hComb`.

## Why baseline + chain (Phase 1 step 6 hole fix)
Old hole: Boss compared only vs chain. Honest Checker anchoring edited hash still matched -> GREEN.
Fix: Boss compares vs enrolled golden baseline. Chain=timeline, baseline=goodness. Need both.

## Enrollment (Phase 0, trusted)
1. Clean room: `hBin0,hCfg0,hMem0,hComb0` via `Enroller`.
2. `config/baseline.json` = `{agentId,seq:0,ts,hBin,hCfg,hMem,hComb,prevHash:zeros}` - Boss trusted store, never overwritten from chain.
3. `Integrity.enroll()` pins genesis on chain.
4. Checker gets privKey, Boss gets pubKey + baseline + contractAddr.

## Steady check - Boss independent re-measure, then
1. `hComb == SHA256(raws)` both sides, else `COMB_MISMATCH`.
2. `Verify(pub, full 8-field payload, sig)` else `SIG_FAIL`.
3. `prevHash == expectedPrev` else `PREV_HASH_BREAK` (missing/forked cycle).
3b. If anchored on-chain: `getLatest` readback equals submitted record, else `CHAIN_MISMATCH` (component: chain).
4. Per-component `H_re vs reported`: `MEASURE_MISMATCH_BIN/CFG/MEM` (lying Checker - tells which).
5. Per-component `reported vs baseline`: `POLICY_BIN_CHANGED/CFG_CHANGED/MEM_CHANGED` (honest report, dirty state - tells which).
6. `ts fresh + seq monotonic` else `STALE_REPLAY`.

Chain cursor (`expectedPrev`, `lastSeq`) advances on OK **and** on POLICY_* so sustained tamper stays `POLICY_CFG_CHANGED` instead of flipping to `PREV_HASH_BREAK`. Dashboard shows `changed: binary|config|memory`.

## Attack table
| Attack | Result |
|---|---|
| Clean | GREEN OK |
| Edit config, honest Checker | RED POLICY_CFG_CHANGED comp=config, sustained |
| Edit binary | RED POLICY_BIN_CHANGED comp=binary |
| Flip memory var | RED POLICY_MEM_CHANGED comp=memory |
| Lying Checker (anchor old) | RED MEASURE_MISMATCH_* comp=that component |
| Replay old payload | RED STALE_REPLAY |
| Drop cycle / fork prev | RED PREV_HASH_BREAK |

## One-liner
"Sig covers all three hashes plus seq/ts/prevHash. Boss tells binary vs config vs memory, chain proves order, baseline proves good."
