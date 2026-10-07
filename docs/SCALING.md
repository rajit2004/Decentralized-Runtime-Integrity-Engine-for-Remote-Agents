# Scaling - Merkle Batching (must-fix flaw)

## Flaw
Anchoring every 5s per device on-chain does not scale.
10,000 devices = 10,000/5 = **~2,000 TPS** - far too many and far too costly on a public chain.

## Fix: batch (implemented)
Collect all devices' `hComb` for a window, build one Merkle tree, anchor **only the root once per minute**.
Each device receives its Merkle proof for that window (`BatchCollector.proofs()`). Cost drops 120,000x, any single
measurement still provable via `MerkleTree.verify(leaf, proof, index, root)`.

- Leaf model: one leaf = raw32(hComb), one leaf per device per window; a device's proof stays valid until the next root replaces it.
- Leaf = raw32(hComb). Parent = SHA256(leftRaw||rightRaw). Odd duplicated. Hex lowercase.
- Single-device mode keeps the 5s heartbeat as today; batch path runs alongside for fleet scale.
- 12-cycle window (60s @5s): root + 12 proofs, 1 tx/min.
- 10k-device window: root in 93ms, proof 44ms, verify ~0ms, proofLen 14.

## Numbers
naive 2000 TPS vs batched 0.0167 TPS = **120,000x reduction**.
Model: per-device heartbeat for a single agent, Merkle root per minute for a fleet.
