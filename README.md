# Decentralized Runtime Integrity Engine for Remote Agents — Track 1.6

> Technorazz 2026 • Hack The Gap • Track 1: Cybersecurity & Blockchain • Problem 1.6

Prove a remote agent has not been tampered with — without trusting the remote machine.

One loop, every 5 seconds: **H-S-A-V — Hash, Sign, Anchor, Verify.**

## What it does
- **Worker (Agent):** dummy Java program + `config.json` + 2-3 critical memory values.
- **Checker:** takes SHA-256 fingerprints of binary + config + canonical memory JSON.
- **Diary (Blockchain):** anchors `hash + timestamp + signature` on local Anvil/Hardhat chain (`Integrity.sol`).
- **Boss (Verifier + Dashboard):** re-computes, verifies Ed25519 seal, compares vs chain. GREEN = OK, RED = TAMPERED in <5s.

We detect tampering, we don't prevent it.

## Stack (zero-download Java core)
- Java 17+ (runs on 24) — JDK only: `MessageDigest`, `Signature Ed25519`, `HttpClient`, `HttpServer`. No Maven/Gradle download needed for MVP.
- Solidity `Integrity.sol` + Hardhat/Anvil local node + Node deploy script (ethers).
- Dashboard: JDK `HttpServer` on `:8080` (no Spring/Javalin needed for hackathon speed).

## Repo layout (built commit-by-commit)
```
README.md
contract/Integrity.sol        # diary
java/src/...                  # agent, measurer, signer, anchor, verifier, dashboard
config/agent-config.json
scripts/
docs/
```

## Quick run (after full build)
```powershell
# terminal 1 - chain
npx hardhat node
# terminal 2 - deploy
node scripts/deploy.js
# terminal 3 - engine
javac -d out (Get-ChildItem -Recurse java/src/*.java)
java -cp out integrity.Main
# open http://localhost:8080
# edit config/agent-config.json -> RED in <5s
```

## Commit policy
Logical commits only, no dumps. One feature = one commit:
1. `chore: init skeleton`
2. `feat(contract): Integrity.sol`
3. `feat(core): measurer`
4. `feat(security): signer`
5. etc.

## Judging fit
- 35% demo: GREEN -> edit file live -> RED with tx hash
- 25% depth: why chain>DB, nonce+timestamp anti-replay, whitelisted memory hashing
- 20% understanding: threat model (attacker can write files, can't rewrite chain/steal privkey)
