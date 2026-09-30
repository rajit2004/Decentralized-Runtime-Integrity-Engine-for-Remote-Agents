<p align="center">
  <img src="assets/logo.png" alt="Integrity Engine" width="120" />
</p>

<h1 align="center">Decentralized Runtime Integrity Engine</h1>

<p align="center">
  <strong>Proof your remote agent hasn't been touched. No trust in the remote machine.</strong>
</p>

<p align="center">
  <a href="#-features"><img src="https://img.shields.io/badge/Features-H_S_A_V-6DB33F?style=flat-square" alt="Features" /></a>
  <a href="#-how-it-works"><img src="https://img.shields.io/badge/How_It_Works-Baseline_Plus_Chain-FF6F61?style=flat-square" alt="How It Works" /></a>
  <a href="#-tech-stack"><img src="https://img.shields.io/badge/Tech_Stack-Java_JDK_Only-4FC3F7?style=flat-square" alt="Tech Stack" /></a>
  <a href="#-project-structure"><img src="https://img.shields.io/badge/Structure-7_Files-FFB74D?style=flat-square" alt="Structure" /></a>
  <a href="#-quick-start"><img src="https://img.shields.io/badge/Quick_Start-5_Min-81C784?style=flat-square" alt="Quick Start" /></a>
  <a href="#-verdict-codes"><img src="https://img.shields.io/badge/Verdicts-AB47BC?style=flat-square" alt="Verdicts" /></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/track-1.6_Cybersecurity-blue.svg?style=flat-square" alt="Track" />
  <img src="https://img.shields.io/badge/made_with-Java_17+-red?logo=openjdk&style=flat-square" alt="Java" />
  <img src="https://img.shields.io/badge/chain-Hardhat_Anvil-yellow?logo=ethereum&style=flat-square" alt="Chain" />
  <img src="https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square" alt="License" />
</p>

---

## What is This?

**Decentralized Runtime Integrity Engine** is a verifiable integrity framework for remote agents built for Technorazz 2026, Track 1.6.

Remote agents — AI bots, edge workers, enterprise daemons — run where you can't see them. An attacker with file access can patch the binary, edit `config.json`, or flip an in-memory limit. How do you know?

We don't prevent the edit. We **prove it happened in under 5 seconds**.

Every 5 seconds the Checker takes 3 fingerprints, seals them, pastes them in a notebook nobody can erase (blockchain), and the Boss compares fresh fingerprints against that notebook **and** against a golden baseline enrolled on day one.

> Chain proves *timeline*. Baseline proves *what good looks like*. You need both.

If you only check chain, an honest Checker anchoring a new edited hash would still look GREEN. That's the hole judges will probe. We fixed it: Boss requires `H_recomputed == H_chain == H_baseline`.

Built with **pure JDK Java (no Maven downloads)**, **Solidity Integrity.sol**, and **Hardhat/Anvil local chain**.

---

## Features

### Core Features

* **Triple Fingerprinting**
  Every cycle hashes the agent binary file, `config/agent-config.json`, and whitelisted memory state (`mode, limit, version`). Uses `MessageDigest SHA-256`. One byte change flips the whole hash.

* **Deterministic Memory Hashing**
  We don't dump RAM — that's noisy. We serialize only critical variables via sorted `TreeMap` to `k=v;k=v` canonical form, then hash. Same state always gives same hash, no false positives.

* **Golden Baseline Enrollment**
  Phase 0 runs once in a clean room. `Enroller.java` captures `H_bin0, H_cfg0, H_mem0, H_comb0` into `config/baseline.json`. That file is the Boss's trusted store, never overwritten from chain. Legit upgrades need a new admin-signed enrollment.

* **Wax-Seal Signatures (frozen)**
  Payload `agentId|seq|ts|hBin|hCfg|hMem|hComb|prevHash` is signed with Ed25519 (`java.security`, no libs). All three component hashes covered, so Boss can blame binary vs config vs memory. `hComb = SHA256(raw32||raw32||raw32)`. Timestamp + monotonic `seq` + `prevHash` chain stops replay/fork.

* **Tamper-Evident Diary**
  `ChainAnchor.java` probes local chain (`eth_blockNumber` on `:8545`) and appends to `ledger.jsonl` always, so demo survives even if Anvil dies. Full contract call is `Integrity.sol.anchor()` with `enroll()` for genesis. Diary is append-only.

* **Judge-Proof Verifier (per-component blame)**
  `Verifier.java` loads golden `hBin/hCfg/hMem/hComb` once (immutable). GREEN only if: 1) `hComb==SHA256(raws)`, 2) full 8-field seal valid, 3) `prevHash` chains, 4) `H_re==reported` per-component (catches lying Checker as `MEASURE_MISMATCH_BIN/CFG/MEM`), 5) `reported==baseline` per-component (catches edit as `POLICY_BIN/CFG/MEM_CHANGED`), 6) `ts` fresh + `seq` monotonic.

* **Live GREEN / RED Dashboard**
  JDK `HttpServer` on `:8080`, zero deps. Big status light, cycle count, tx hash, expected-baseline vs observed vs chain (truncated), detail line with timings. Auto-refreshes every 2s. This is what judges stare at.

* **Live Tamper Demo**
  Edit `config/agent-config.json` from `100` to `999` and save. Next cycle (<5s) flips to RED `POLICY_MISMATCH expected c9be…aff2 got 7c21…`. Restore file, back to GREEN. No restart needed.

* **Lying-Checker Detection**
  If Checker is compromised and anchors old good hash while files are dirty, Boss independent re-measurement catches it: `MEASURE_MISMATCH`. Two measure calls per cycle, not one.

* **Metrics on Every Cycle**
  Console + dashboard show `measure Xms, verify Yms, chainUp true/false, detection < polling`. Typical laptop: measure ~5-15ms, verify ~2ms, anchor ~200ms local.

### Reliability and Safety

* **No External Java Deps**
  Pure JDK 17+ (runs on 24). No Maven, Gradle, Spring, or web3j download needed for MVP. `javac` + `java` is enough. Perfect for hackathon wifi.

* **Chain Fallback**
  If `:8545` is down, engine keeps running on `ledger.jsonl` fallback and marks `chainUp=false`. You lose decentralization points but keep 35% demo marks.

* **Stale / Replay Guard**
  Rejects old timestamps (>30s) and reused nonces. Attacker can't resend last week's good cover.

* **Windows-Safe Paths**
  Hashes `AgentState.java` source + config instead of locked `.exe`. Avoids file-lock false REDs on Windows demo laptops.

### Design Choices

* **Detect, Don't Prevent**
  We state this upfront. Threat model: attacker can write files, can't steal private key, can't rewrite chain history, can't rewrite Boss baseline store.

* **Small Attack Surface**
  7 Java files, 1 Solidity file. Each file has one job. Easy for any teammate to explain heartbeat in viva.

---

## How It Works

```text
Phase 0 — Trusted Enrollment (once)
  Clean room -> Enroller measures golden files
        |
        v
  config/baseline.json saved with Boss + genesis anchored
        |
        v
Phase 1 — Heartbeat (every 5s forever)
  Checker reads binary + config + memory
        |
        v
  H_bin, H_cfg, H_mem -> H_comb
        |
        v
  Sign(agentId|H_comb|ts|nonce) with privateKey
        |
        v
  Anchor(H_comb, nonce, sig) to Integrity.sol / ledger.jsonl
        |
        v
  Boss independently re-reads files -> H_re
        |
        v
  4 checks: seal valid? H_re==H_chain? H==baseline? fresh?
        |
        v
  GREEN (all pass) or RED (reason + expected vs got)
        |
        v
  Dashboard :8080 + console log
```

Attack table for viva:

| Attack | H_re | H_chain | H_base | Result |
|---|---|---|---|---|
| No attack | A | A | A | GREEN |
| Edit config, honest Checker | B | B | A | RED POLICY_MISMATCH |
| Edit config, lying Checker | B | A | A | RED MEASURE_MISMATCH |
| Replay old payload | A_old | A_old | A | RED STALE/REPLAY |

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Language** | Java 17+ (tested on 24), JDK only |
| **Crypto** | `MessageDigest SHA-256`, `Signature Ed25519` |
| **Chain** | Solidity 0.8.20 `Integrity.sol`, Hardhat / Anvil local node |
| **Chain Client** | Java `HttpClient` JSON-RPC probe + Node ethers deploy script |
| **Dashboard** | Java `HttpServer` on `:8080`, no framework |
| **Canonicalization** | `TreeMap` sorted `k=v;` (no Jackson needed) |
| **Config** | `config/agent-config.json`, `config/baseline.json` |
| **Fallback Ledger** | `ledger.jsonl` append-only |

---

## Project Structure

```text
1.6/
├── contract/
│   ├── Integrity.sol             # diary: enroll() + anchor() + events
│   ├── hardhat.config.js
│   ├── package.json
│   └── scripts/deploy.js         # deploys to localhost:8545
├── java/src/integrity/
│   ├── Main.java                 # heartbeat loop + wiring
│   ├── measure/Measurer.java     # SHA-256 triple fingerprint
│   ├── sign/Signer.java          # Ed25519 seal + verify
│   ├── enroll/Enroller.java      # Phase 0 golden capture
│   ├── chain/ChainAnchor.java    # chain probe + ledger.jsonl fallback
│   ├── verify/Verifier.java      # 4-check judge-proof verifier
│   ├── agent/AgentState.java     # dummy worker whitelisted state
│   └── ui/Dashboard.java         # GREEN/RED page :8080
├── config/
│   ├── agent-config.json         # tamper target (edit live)
│   └── baseline.json             # goldenпия, Boss trusted store
├── docs/
│   └── VERIFICATION_LOGIC.md     # why baseline + chain
├── scripts/                      # (demo helpers)
└── README.md
```

---

## Quick Start

### Prerequisites

* Java 17+ (`java -version`)
* Node 18+ + npm (only for chain, optional for fallback demo)
* No Maven/Gradle needed

### 1. Clone

```bash
git clone https://github.com/rajit2004/Decentralized-Runtime-Integrity-Engine-for-Remote-Agents.git
cd Decentralized-Runtime-Integrity-Engine-for-Remote-Agents
```

### 2. Enroll Golden Baseline (trusted, once)

```powershell
javac -d out (Get-ChildItem -Recurse java/src/*.java)
java -cp out integrity.enroll.Enroller "java/src/integrity/agent/AgentState.java" "config/agent-config.json"
# check config/baseline.json -> hComb golden
```

Re-run this only for legit upgrades. Never auto-overwrite from chain.

### 3. Start Chain (optional but recommended)

```bash
cd contract
npm install
npx hardhat node
# new terminal
node scripts/deploy.js
# save printed address into docs / config
```

If chain is down, engine still runs with `chainUp=false` + `ledger.jsonl`.

### 4. Run Engine

```powershell
javac -d out (Get-ChildItem -Recurse java/src/*.java)
java -cp out integrity.Main
```

Open:

```text
http://localhost:8080
```

You should see GREEN flowing with cycle + tx.

### 5. Tamper Live (the demo)

1. Open `config/agent-config.json`, change `"threshold": 100` to `999`, save.
2. In <5s dashboard flips RED: `POLICY_MISMATCH expected c9be…aff2 got …`.
3. Restore to `100`, save. Back to GREEN next cycle.

Show judges `baseline.json` on screen before step 1 — that proves what good is.

---

## Verdict Codes

All from `Verifier.java`:

* `OK` — all 4 checks pass, GREEN
* `SIG_FAIL` — wax seal invalid, key mismatch or forged payload
* `MEASURE_MISMATCH` — `H_re != H_chain`, Checker lied or MITM. Expected = chain, observed = recomputed.
* `POLICY_MISMATCH` — honest report but dirty state. Expected = baseline golden, observed = recomputed. This is normal file-edit attack.
* `STALE_REPLAY` — old timestamp or reused nonce.

Contract API (`Integrity.sol`):

* `enroll(agentId, hBase)` — once, cycle 0 genesis
* `anchor(agentId, hComb, nonce, sig)` — every heartbeat
* `getLatest(agentId)` — returns `(hComb, ts, sig, nonce)`
* Events: `Enrolled`, `Anchored`

---

## Deployment

Demo laptop is production for hackathon.

```powershell
# build
javac -d out (Get-ChildItem -Recurse java/src/*.java)
# run
java -cp out integrity.Main
```

For real deployment (beyond hackathon): split Checker and Boss onto separate hosts, store private key in TPM/HSM, store baseline + public key in Boss vault, run Anvil/Hardhat as real L2 or permissioned chain, add Prometheus metrics. See Stretch: real TPM/TEE attestation, low-overhead measurement, secret sealing.

---

## Contributing

Logical commits only, no dumps. One feature = one commit.

```bash
git checkout -b feat/amazing-check
git commit -m "feat(verify): explain policy mismatch better"
git push origin feat/amazing-check
```

Never commit real `*.key` files. Demo keys are ephemeral per run.

---

## License

Distributed under the **MIT License**.

---

## Acknowledgements

* **Hardhat / Foundry Anvil** for local chain
* **Java JDK** `MessageDigest`, `Ed25519`, `HttpServer` — zero-dep MVP
* **Technorazz 2026 Technorazz team** for Track 1.6 problem statement

---

## Author

**Rajit + Team**
Track 1.6 — Decentralized Runtime Integrity Engine for Remote Agents

[![GitHub](https://img.shields.io/badge/GitHub-rajit2004-black?style=flat&logo=github)](https://github.com/rajit2004/Decentralized-Runtime-Integrity-Engine-for-Remote-Agents)

> One-liner for viva: *"Chain proves timeline. Baseline proves goodness. We check both, with independent re-measurement, every 5 seconds."*
