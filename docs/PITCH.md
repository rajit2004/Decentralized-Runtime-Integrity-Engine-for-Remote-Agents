# Pitch — Decentralized Runtime Integrity Engine (Track 1.6)
**Slot: 5–10 minutes → timed for 8 minutes, with one interruption of slack.**

---

## 30-Second Elevator
> "You run AI agents on machines you don't own. You can't stop someone from editing them — but we prove it happened in 5 seconds, with cryptographic evidence nobody can erase. One dashboard, one click, and the screen turns red with the exact file that changed."

---

## Timed Script

### 0:00–0:30 — Hook (do this first, don't talk over the demo)
*Dashboard is already live, green, on screen. Set it up BEFORE you walk on stage.*

> "This is our remote agent, healthy. Every 5 seconds it fingerprints itself, signs it, and stores it where nobody can rewrite history.
>
> Now watch — I'm going to change **one number** in its config. A real attacker's first move."

**Click "Tamper config file."** *(RED within one 5s heartbeat)*

> "Detected. Names the file: config. Not in 5 minutes — in one heartbeat, with a signed, timestamped proof.
>
> And I didn't stop the attack. **We don't prevent tampering. We prove it.** That's the honest design."

*(Click "Restore config" → GREEN returns. Keep talking.)*

### 0:30–2:00 — Problem
> "Remote agents — AI bots, edge workers, enterprise daemons — run outside your control. Anyone with file access can patch the binary, rewrite the config, flip a memory value.
>
> The obvious fix is a database log. **That fails**, because the log lives on the same machine as the attacker. If they can edit the config, they can edit the audit trail. You can't audit an audit log that the enemy owns.
>
> What you need is *tamper-evidence*: an append-only record the attacker can't rewrite, plus something that says what 'good' looked like on day one. That's the problem statement 1.6, and that's exactly what we built."

### 2:00–3:30 — Solution (H-S-A-V)
> "Four steps, every 5 seconds:
>
> 1. **Hash** — fingerprints of three things: the binary, the config, and the whitelisted memory state. One byte changes, the fingerprint is completely different.
> 2. **Sign** — we sign `agentId | seq | timestamp | all three hashes | previous hash`. A signature covering everything, so we can say **which** part changed — binary, config, or memory.
> 3. **Anchor** — the signed measurement goes to a chain. Append-only, timestamped, ordered.
> 4. **Verify** — an independent verifier re-measures and checks: signature valid? chain intact? **and does it match the golden baseline enrolled on day one?**
>
> Here's the part judges usually probe us on: **why both chain and baseline?**
>
> If you only check the chain, an honest checker anchoring a tampered hash still matches the chain — it looks green forever. The chain proves *order*. The baseline proves *goodness*. You need both. Anyone who skips the baseline ships a demo that can't catch a live edit — we caught that hole ourselves in our first design, and fixed it before anyone else found it."

### 3:30–6:00 — Live demo (guided, hands-free)
*Press "Run config-attack scenario." It narrates itself while you talk.*

> "Hands-free — the dashboard runs the whole attack and recovery while I talk."

*Shows: tamper → RED `POLICY_CFG_CHANGED comp=config` → restore → GREEN.*

**Then memory attack** (`Tamper memory` button):

> "Second flavor — no file touched. I flipped a value **inside the agent's memory**. Watch the verdict change: `POLICY_MEM_CHANGED`, component: memory. We tell you *where* it happened, not just *that* it happened."

**Then stall the heartbeat** (run `scripts/demo-stale.ps1` — locks the config file) → CYCLE_ERR, then STALE in 12s:

> "Third flavor: silence. The checker hangs and stops reporting. We don't keep showing a stale green light: first the exact cause as CYCLE_ERR, then within 12 seconds the watchdog says STALE with the last known hash. Honest dashboards don't lie by omission."
> *(If someone kills the whole process instead, the page says 'engine unreachable' — also honest.)*

*Lock releases → rejoins GREEN, sequence resumes where it left off.*

> "It rejoins without replaying history — sequence persisted, chain linked. A reconnect can't forge the past."

### 6:00–7:00 — Depth and scale
> "Three things that separate this from a weekend demo:
>
> **It catches a lying checker.** The verifier re-measures independently. If the signer on the remote box reports a hash that doesn't match reality, that's a different verdict — `MEASURE_MISMATCH` — because we never trust the reporter's word alone.
>
> **It scales.** One tx per device per 5 seconds at 10,000 devices is 2,000 transactions per second — insane. We batch: one window of hashes becomes one Merkle root per minute. We measured it: 10,000 leaves build in 93 milliseconds, one proof verifies instantly. **120,000x fewer transactions** — from 2000/sec to one per minute, and you can still prove any single measurement with its Merkle proof.
>
> **It's cheap.** 20-trial benchmark: 4 milliseconds average per cycle, 24 worst. Detection lands inside the 5-second heartbeat. The security costs single-digit milliseconds."

### 7:00–7:45 — Honest limits (say them BEFORE judges ask)
> "What we'd be dishonest not to say:
>
> 1. **The checker signs with a key on the same machine** — a determined root attacker can steal it. The real fix is hardware: TPM/TEE attestation. That's our roadmap, and it slots into our trust anchor without redesign.
> 2. **Memory is a whitelist**, not a heap dump. Full RAM never hashes twice the same way — GC, counters, ASLR. So we hash what matters and say so.
> 3. **The independent re-read is a same-laptop demo trick.** A real remote verifier works from the signed measurement, baseline, and chain only. We've documented every limit in `docs/THREAT_MODEL.md` — and we'd rather volunteer them than get caught."

### 7:45–8:00 — Ask / close
> "We built the trust anchor and proved the loop works. The next step is putting the key in hardware and running it against a real edge fleet.
>
> **We don't prevent tampering. We prove it — in 5 seconds, from anywhere.**"

---

## 10-Slide Outline (for the deck)

1. **Title** — name, track 1.6, team, one-liner: *"Prove tampering in 5 seconds."*
2. **Problem** — agents outside control; DB logs live with the attacker → rewriteable.
3. **Attack, live** — screenshot of RED `POLICY_CFG_CHANGED comp=config`.
4. **Solution: H-S-A-V** — Hash → Sign → Anchor → Verify, 5s loop diagram.
5. **Why chain + baseline** — chain = order, baseline = good; the chain-only hole explained.
6. **Demo** — 4 states: GREEN / POLICY config / POLICY memory / STALE, all from one screen.
7. **Depth** — per-component blame, lying-checker detection, seq+prevHash chain, watchdog.
8. **Scale** — Merkle batching: 2000 TPS → 1 tx/min, 120,000x, 93ms for 10k leaves.
9. **Numbers** — 4ms avg / 24ms worst pipeline, 5s interval, 12s STALE, 20 trials.
10. **Honest limits + next** — TPM/TEE roadmap, whitelist, demo-only re-read, the ask.

---

## Q&A Card — 8 questions judges will ask

**Q: Why blockchain instead of a database?**
> "Because the attacker owns the machine. A Postgres row lives next to the config they edit. Our record is append-only and timestamped elsewhere — and the file fallback is labeled tamper-*evident*, not tamper-proof, because we're honest about that too."

**Q: How fast is detection, really?**
> "Measured over 20 trials: 4ms pipeline average, 24ms worst, inside a 5-second heartbeat. No flat '<5s' claim — interval plus pipeline, and STALE after 12 seconds of silence from the checker."

**Q: What's fake in this demo?**
> "Three things, said first: same-machine re-read, whitelisted memory instead of heap, and software keys instead of TPM. Everything else is real SHA-256, real Ed25519, real contract calls."

**Q: What stops replay of an old good measurement?**
> "Signed payload includes sequence, timestamp, and the previous hash. Old sequence → REPLAY verdict. Old timestamp → REPLAY. Forked history → prevHash break. Three doors, all locked."

**Q: Does this scale? What's the cost?**
> "Batched: one Merkle root per minute for the whole fleet instead of a tx per device. 10k leaves build in 93ms, 120,000x fewer transactions, and any single measurement is still provable with its proof."

**Q: Why Java?**
> "JDK-only — MessageDigest, Ed25519, HttpServer ship in the box. Zero downloads on conference wifi. Nothing about the design needs a framework."

**Q: What if the chain goes down?**
> "The engine keeps running on a local fallback ledger and flags `chainUp=false` on screen. Demo survives, and we label the fallback honestly — chain event log stays authoritative."

**Q: What's the actual innovation here?**
> "The dual-anchor verification: chain proves order AND baseline proves goodness, plus per-component blame so you learn *which* of binary/config/memory changed — while stating every trust limit up front instead of hiding it."

---

## Rehearsal checklist (do before you walk on)

- [ ] Kill orphan java, one engine only: `Get-Process -Name java | Stop-Process -Force`
- [ ] Pull, rebuild, re-enroll if source/config changed: `scripts/run.ps1`
- [ ] Baseline green on `http://localhost:8080`, page loaded, presenter mode ready
- [ ] Scenario button tested once (config attack → RED → GREEN)
- [ ] Memory button tested once; restore endpoint works
- [ ] Screenshots of all 4 states saved — fallback if demo gods misbehave
- [ ] Time the full run: hook + demo must fit your slot with interruption slack
- [ ] One teammate assigned as Q&A responder for bench/scale questions while presenter drives demo
