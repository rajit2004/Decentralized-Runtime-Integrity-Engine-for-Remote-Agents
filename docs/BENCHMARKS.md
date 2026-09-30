# Benchmarks — Item 4 (20 trials, laptop)

Frozen timing: **interval 5s, STALE if no fresh anchor after 12s.**
Headline reworded: detection lands **within one 5s interval plus pipeline**,
NOT "RED in <5s" flat. Worst case = interval + pipeline worst.

## Pipeline (measure+sign+verify, 20 trials, Windows laptop, JDK 24)
```
trial=1 measure=1ms sign=10ms verify=10ms
trial=2..20 measure 0-4ms, sign 1-3ms, verify 1-3ms
AVG measure=0.6ms worst=4ms
AVG sign=1.6ms worst=10ms
AVG verify=2.0ms worst=10ms
PIPELINE avg=4ms worst=24ms
```
- Typical detection after file edit: **next cycle, ~5.0s + ~4ms**.
- Worst observed: **5024ms** (5s interval + 24ms pipeline).
- STALE (checker killed): watchdog 1s tick, dashboard STALE after **12s** with no fresh anchor.

## Merkle batch (scale fix)
```
10k leaves: buildMs=93 proofMs=44 verifyMs=0 proofLen=14 verify=true
naive=2000.0 TPS vs batched=0.0167 TPS reduction=120000x
12 leaves (60s @5s single device): buildMs=6 proofMs=2 verifyMs=2
```
Run: `java -cp out integrity.batch.BatchBench 10000`, `java -cp out integrity.batch.Bench20`.

## What to tell judges
"5s heartbeat, ~4ms pipeline avg, ~24ms worst, STALE after 12s. Batch path: 10k-device window builds in 93ms, 1 root/min."
