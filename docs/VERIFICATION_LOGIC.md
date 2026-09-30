# Verification Logic — Why Baseline + Chain (Fix for Phase 1 Step 6 Hole)

## The hole
Old text: "Boss re-reads files and compares against chain."
Problem: if attacker edits `config.json`, honest Checker anchors NEW hash, Boss recomputes SAME new hash, they match -> stays GREEN. Demo would fail.

## The fix
Boss compares against **enrolled baseline** captured at Phase 0 in a trusted environment.

- **Chain proves timeline:** what was reported, when, by whom, with no rollback/erase.
- **Baseline proves goodness:** what the golden binary/config/memory hashes *should* be.

Need both. Either alone fails.

## Enrollment (Phase 0, trusted)
1. In clean room, compute `H_bin0, H_cfg0, H_mem0, H_comb0`.
2. Admin signs enrollment: `Enroll{agentId, H_comb0, ts0}`.
3. Store in Boss trusted store: `config/baseline.json` (read-only in demo) + anchor genesis `H_comb0` on chain as cycle 0.
4. Distribute: Checker gets `privateKey`, Boss gets `publicKey + baseline.json + contractAddr`.

Baseline update (legit upgrade) requires new admin-signed enrollment. Not covered by normal heartbeat.

## Steady check (Phase 1, every 5s) — all 4 must pass
Given `H_re` = Boss independent re-measurement, `H_chain` = latest on-chain hash, `H_base` = enrolled baseline:

1. `Verify(pubKey, agentId|H_chain|ts|nonce, sig)` == true → origin OK, else `SIG_FAIL`
2. `H_re == H_chain` → reporting honest, else `MEASURE_MISMATCH` (lying Checker / MITM)
3. `H_re == H_base && H_chain == H_base` → state golden, else `POLICY_MISMATCH expected <H_base> got <H_re>`
4. `now - ts < STALE_TIMEOUT && nonce > lastNonce` → fresh, else `STALE/REPLAY`

Verdict GREEN only if 1+2+3+4 pass.

## Attack table (for viva)
| Attack | H_re | H_chain | H_base | Result |
|---|---|---|---|---|
| No attack | A | A | A | GREEN |
| Edit config, honest Checker | B | B | A | RED POLICY_MISMATCH (2 passes, 3 fails) |
| Edit config, lying Checker anchors old A | B | A | A | RED MEASURE_MISMATCH (2 fails) |
| Replay old good payload | A_old | A_old | A | RED STALE/REPLAY (4 fails) |
| Rewrite chain history | — | — | — | fails: local Anvil append-only + tx receipt check |

## What to tell judges
"Chain alone tells us *when* something was said. Baseline tells us *what good looks like*. We check both, plus independent re-measurement so a compromised Checker can't lie."

## Implementation pointers
- `Enroller.java` → writes `config/baseline.json` once.
- `Verifier.java` → loads baseline at startup (immutable), does 4 checks, never updates baseline from chain.
- `Dashboard.java` → shows `expected (baseline short) vs observed (recomputed short) vs chain short` on RED.
- Demo: show `baseline.json` on screen before tamper, then edit config → RED shows mismatch vs that baseline.
