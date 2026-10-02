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

We don't prevent the edit. We **prove it within one 5s interval plus ~4ms pipeline avg (~24ms worst, measured 20 trials). STALE if no fresh anchor after 12s.**

Every 5 seconds the Checker takes 3 fingerprints, seals them, pastes them in the chain event log (authoritative; `ledger.jsonl` is a tamper-evident FALLBACK, not tamper-proof), and the Boss compares fresh fingerprints against that log **and** against a golden baseline enrolled on day one.

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

* **Tamper-Evident Diary (chain authoritative, file fallback)**
  `ChainAnchor.java` sends a real `anchor()` tx every cycle when `config/chain.json` + node are up (`ledgerRef` = tx hash, `block.timestamp` authoritative), and appends to `ledger.jsonl` FALLBACK always so demo survives Anvil death. History lives in `Anchored` events (event log); mapping holds latest only. Ed25519 verified OFF-CHAIN by Boss (EVM has none). File ledger is tamper-evident, not tamper-proof — Verifier `headHash()` memory catches rewrites within a run.

* **Judge-Proof Verifier (per-component blame)**
  `Verifier.java` loads golden `hBin/hCfg/hMem/hComb` once (immutable). GREEN only if: 1) `hComb==SHA256(raws)`, 2) full 8-field seal valid, 3) `prevHash` chains, 4) `H_re==reported` per-component (catches lying Checker as `MEASURE_MISMATCH_BIN/CFG/MEM`), 5) `reported==baseline` per-component (catches edit as `POLICY_BIN/CFG/MEM_CHANGED`), 6) `ts` fresh + `seq` monotonic.

* **Live GREEN / RED Dashboard**
  JDK `HttpServer` on `:8080`, zero deps. Big status light, cycle count, tx hash, expected-baseline vs observed vs chain (truncated), detail line with timings. Auto-refreshes every 2s. This is what judges stare at.

* **Live Tamper Demo (3 flavors)**
  Config: edit `config/agent-config.json` `100->999`, save. Next 5s cycle flips RED `POLICY_CFG_CHANGED comp=config`. Memory: open `/tamper/memory?limit=999` (no file edit) -> RED `POLICY_MEM_CHANGED`. Binary: main demo is config (JAR locked on Windows; test binary tamper on Linux/macOS or stopped agent). Restore -> GREEN. No restart.

* **Lying-Checker Detection**
  If Checker anchors old good hash while files dirty, Boss independent recompute (demo only — remote has signed measurement only) catches `MEASURE_MISMATCH_BIN/CFG/MEM` and names the component. Two measure calls per cycle.

* **Keys Outside Writable Dir (stated assumption)**
  Private key in `keys/` (locked perms where OS allows), NOT next to `config.json`. A box-reader can still steal it — TPM/TEE is the real fix (stretch). Stated openly, see `docs/THREAT_MODEL.md`.

* **Metrics on Every Cycle (measured, not promised)**
  20 trials: pipeline avg 4ms (measure 0.6, sign 1.6, verify 2.0), worst 24ms. Detection = next 5s interval + pipeline. STALE after 12s via 1s watchdog. Batch: 10k-leaf root 93ms, 1 root/min = 0.0167 TPS vs naive 2000 TPS (120,000x). See `docs/BENCHMARKS.md`.

* **Scale: Merkle Batching**
  Fleet fix: collect window of `hComb`, anchor one root/min, keep per-device proofs. Demo heartbeat stays 5s; batch path proves 10k scale. See `docs/SCALING.md`.

### Reliability and Safety

* **No External Java Deps**
  Pure JDK 17+ (runs on 24). No Maven, Gradle, Spring, or web3j download needed for MVP. `javac` + `java` is enough. Perfect for hackathon wifi.

* **Real Chain Anchoring**
  With `config/chain.json` (written by `npm run deploy`) and the node up, every heartbeat is a real `anchor()` transaction: `ledgerRef` = tx hash, chain `block.timestamp` authoritative (`chainUp=true`). If the node is down, engine keeps running on `ledger.jsonl` fallback and marks `chainUp=false`. You lose decentralization points but keep 35% demo marks.

* **Stale / Replay Guard**
  Rejects timestamps older than 12s (chain `block.timestamp` authoritative when up) and reused/rewound `seq`. Attacker can't resend last week's good cover. `seq` persisted in `config/seq.dat` so restarts don't self-flag REPLAY.

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
  H_bin, H_cfg, H_mem -> H_comb=SHA256(raw32||raw32||raw32)
        |
        v
  Sign(agentId|seq|ts|hBin|hCfg|hMem|hComb|prevHash) with keys/ privateKey
        |
        v
  Anchor full JSON to Integrity.sol (owner-only, block.timestamp) / ledger.jsonl FALLBACK
        |
        v
  Boss independent recompute, demo only (remote has signed measurement only) -> H_re
        |
        v
  Checks: comb valid? full seal valid (off-chain)? prevHash chains? H_re==reported per-component? reported==baseline per-component? seq/ts fresh (chain time authoritative)?
        |
        v
  GREEN (all pass) or RED (reason + expected vs got)
        |
        v
  Dashboard :8080 + console log
```

Attack table for viva:

| Attack | Result |
|---|---|
| No attack | GREEN OK |
| Edit config, honest Checker | RED POLICY_CFG_CHANGED comp=config, sustained |
| Edit binary | RED POLICY_BIN_CHANGED comp=binary |
| Memory flip via endpoint | RED POLICY_MEM_CHANGED comp=memory |
| Lying Checker (anchor old) | RED MEASURE_MISMATCH_* comp=that component |
| Replay / reorder | RED STALE_REPLAY (seq/ts/prevHash) |
| Heartbeat stalled (locked/hung files) | RED CYCLE_ERR, then STALE after 12s via 1s watchdog (headHash shown). Demo: `scripts/demo-stale.ps1` |

---

## Tech Stack

| Layer | Technology |
|---|---|
| **Language** | Java 17+ (tested on 24), JDK only |
| **Crypto** | `MessageDigest SHA-256`, `Signature Ed25519` |
| **Chain** | Solidity 0.8.20 `Integrity.sol`, Hardhat / Anvil local node |
| **Chain Client** | Java `HttpClient` JSON-RPC probe + Node ethers deploy script |
| **Dashboard** | Java `HttpServer` on `:8080`, no framework |
| **Canonicalization** | Manual `TreeMap` sorted `k=v;` — no Jackson (SORT_KEYS trap avoided by design) |
| **Config** | `config/agent-config.json`, `config/baseline.json` (golden), `config/seq.dat` (persisted cursor) |
| **Keys** | `keys/` outside writable `config/` (assumption stated; TPM/TEE real fix) |
| **Batch** | `batch/MerkleTree` root/min + proofs (10k scale) |
| **Fallback Ledger** | `ledger.jsonl` FALLBACK tamper-evident (headHash in memory), chain event log authoritative |
| **Timing** | 5s interval, STALE after 12s, 1s watchdog; pipeline avg 4ms worst 24ms |

---

## Project Structure

```text
1.6/
├── contract/
│   ├── contracts/Integrity.sol    # diary: enroll() + anchor() + events
│   ├── hardhat.config.js
│   ├── package.json
│   └── scripts/deploy.js         # deploys to localhost:8545, writes config/chain.json
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

A fresh clone boots **GREEN immediately**: the golden baseline is committed, `keys/` auto-generate on first run, and `.gitattributes` pins LF line endings for the hashed files so bytes match on every OS.

### 2. Enroll Golden Baseline (only after changing source/config)

```powershell
javac -d out (Get-ChildItem -Recurse java/src/*.java)
java -cp out integrity.enroll.Enroller "java/src/integrity/agent/AgentState.java" "config/agent-config.json"
# check config/baseline.json -> hComb golden
```

Re-run this only when you intentionally edited `AgentState.java` or `agent-config.json` (legit upgrades). Never auto-overwrite from chain.

### 3. Start Chain (optional but recommended)

```bash
cd contract
npm install
npx hardhat node --port 8545
# new terminal
npm run deploy        # hardhat run scripts/deploy.js --network localhost
# writes ../config/chain.json (rpcUrl, contractAddr, from, gas)
```

Restart the engine after deploy — it reads `config/chain.json`, enrolls once on-chain (`anchorCount==0`), then every 5s heartbeat is a real `anchor()` tx. If chain is down, engine still runs with `chainUp=false` + `ledger.jsonl`.

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
2. Next 5s cycle flips RED: `POLICY_CFG_CHANGED comp=config` (sustained, not one-off). Worst-case detection = 5s + 24ms pipeline; heartbeat stall → CYCLE_ERR, STALE after 12s (`scripts/demo-stale.ps1`).
3. Restore to `100`, save. Back to GREEN next cycle. Memory variant: open `/tamper/memory?limit=999` -> `POLICY_MEM_CHANGED` without file edit.

> **Byte-safety tips (demo insurance):**
> * Easiest: use the dashboard's **Tamper/Restore buttons** — they edit only the value and never touch line endings.
> * If editing manually, use an editor that preserves line endings (VS Code, IntelliJ, Windows 11 Notepad). A CRLF-rewriting editor changes the file's bytes even with `threshold` back at `100`, and the engine will **correctly** stay RED (proof: bytes *did* change).
> * Stuck RED after a bad save? `git checkout -- config/agent-config.json` restores byte-identical bytes -> GREEN next cycle.

Show judges `baseline.json` on screen before step 1 — that proves what good is. Volunteer limits first: compromised Checker can sign lies (TPM/TEE stretch), Boss re-read is demo-only, memory = whitelisted map.

---

## Verdict Codes

All from `Verifier.java`:

* `OK` — all checks pass, GREEN
* `SIG_FAIL` — full 8-field seal invalid (Boss verifies off-chain; EVM has no Ed25519)
* `MEASURE_MISMATCH_BIN/CFG/MEM` — Boss recompute vs reported diverge per-component (lying Checker/MITM)
* `POLICY_BIN/CFG/MEM_CHANGED` — honest report but dirty vs golden baseline per-component
* `COMB_MISMATCH` — `hComb != SHA256(raws)`
* `PREV_HASH_BREAK` — missing/forked cycle (chain linkage)
* `STALE_REPLAY` — old `block.timestamp`-checked time or reused `seq`

Contract API (`Integrity.sol`, owner-only, `block.timestamp` authoritative):

* `enroll(agentId, hBin, hCfg, hMem, hComb)` — once, cycle 0 genesis, sets `ownerOf`
* `anchor(agentId, seq, hBin, hCfg, hMem, hComb, prevHash, sig)` — heartbeat, `require(msg.sender==owner)`, `prevHash` linkage
* `getLatest(agentId)` — returns full `Record`
* Events (history lives here; mapping holds latest only): `Enrolled(bytes32 indexed agentIdHash, ...)`, `Anchored(bytes32 indexed agentIdHash, ...)`

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

New commits only — no amend, no force-push. Never commit `keys/*.pkcs8`, `keys/*.x509`, or real `*.key` files. Demo keys generate once into ignored `keys/`.

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

> One-liner for viva: *"Sig covers all three hashes plus seq/ts/prevHash. Chain proves order, baseline proves good. We name binary vs config vs memory. Limits: Checker can lie without TPM, re-read is demo-only, memory is a whitelist."*

## IntelliJ Troubleshooting

`Error: Could not find or load main class integrity.Main` with no `-classpath` in the launch line means IntelliJ's Make produced nothing. Fix in order:

1. `File -> Project Structure -> Project`: SDK must be JDK 24 (Add SDK -> JDK home `C:\Program Files\Java\jdk-24` if missing). Language level 24.
2. `Modules -> 1.6 -> Sources`: `java/src` must be blue (Sources). If not, right-click -> Mark as Sources Root.
3. `Build -> Rebuild Project`. Verify `out/production/1.6/integrity/Main.class` exists (terminal builds use `out/integrity/`, a different folder — both can coexist).
4. Run config `Run-Engine`: "Use classpath of module: 1.6", Before Launch: Build.
5. Re-run. Fallback that always works: `scripts/run.ps1` in a terminal (all live GREEN/RED tests ran that way).

## Open Limits (volunteer before judges ask)
* Compromised Checker can sign false hashes — TPM/TEE is the stretch goal.
* Boss file re-read works because demo is one laptop; remote verifier uses signed measurement + baseline + chain only.
* Memory = `AgentState{mode,limit,version}` whitelist, not heap (heap never stabilizes).
* `ledger.jsonl` is FALLBACK tamper-evident; chain event log authoritative.
* Stack: JDK-only MVP (`javac`/`java`, no Maven/Spring/Gradle/Javalin/web3j wrapper needed). Binary tamper is secondary on Windows (JAR locked / classes dir); config + memory endpoint are the live demos. File reads retry 200ms; missing file = tamper.
