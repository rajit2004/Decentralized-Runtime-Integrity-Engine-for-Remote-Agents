# Threat Model — Stated Openly (say it before judges do)

## What we assume (and admit)
1. **Item 11 — Compromised Checker can sign lies.** Checker runs on the same box as Worker
   with the private key in `keys/` (outside writable `config/`, locked perms where OS allows).
   A root-level reader can still steal it. We say this first. Real fix = TPM/TEE attestation (stretch).
2. **Item 12 — Boss re-read is demo only.** One-laptop demo lets Boss independently re-read files.
   Real remote verifier has the signed measurement + baseline + chain only. Labeled
   "independent recompute, demo only" in code and dashboard.
3. **Item 13 — "Memory" = whitelisted map.** `AgentState{mode,limit,version}` hashed via sorted
   TreeMap, NOT full heap (GC/counters/ASLR never stabilize). Memory attack simulated via
   `/tamper/memory?limit=999` endpoint + file-config attack. Stated in README + UI.
4. **Item 3 — Key separation.** `keys/` outside attacker-writable `config/`. POSIX owner-only
   perms where available; Windows ACL note. Assumption documented in `KeyStore.java`.
5. **Item 10 — File ledger is fallback, tamper-evident not tamper-proof.** `ledger.jsonl` can be
   rewritten with recomputed hashes. Verifier memory `headHash()` + `prevHash` linkage catches
   rewrites within a run; across restarts it is a demo fallback. Chain event log is authoritative.
   Labeled FALLBACK in dashboard + docs.

## What attacker CAN / CANNOT do
CAN: write `config/`, flip memory via endpoint, hang/stall Checker (STALE after 12s via watchdog), replay old payloads (rejected by seq/ts/prevHash).
CANNOT (assumed): steal `keys/` without trace, rewrite chain event log, rewrite Boss `baseline.json` store.

## Verification (off-chain — item 6)
Ed25519 verified by Boss off-chain (EVM has no native Ed25519). Contract stores + orders + timestamps.
History = `Anchored` event log (item 7); mapping holds latest only.
Freshness = `block.timestamp` authoritative when chainUp (item 8); Checker ts otherwise.
Only `ownerOf` (deployer at enroll) may anchor (item 9).
