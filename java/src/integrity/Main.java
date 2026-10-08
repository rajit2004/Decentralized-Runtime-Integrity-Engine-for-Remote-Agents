package integrity;

import integrity.agent.AgentState;
import integrity.chain.ChainAnchor;
import integrity.enroll.Enroller;
import integrity.enroll.SeqStore;
import integrity.measure.Measurer;
import integrity.measure.SignedMeasurement;
import integrity.sign.KeyStore;
import integrity.sign.Signer;
import integrity.ui.Dashboard;
import integrity.verify.Verifier;
import integrity.witness.Witness;
import com.sun.net.httpserver.HttpServer;
import java.nio.file.*;
import java.security.KeyPair;

/**
 * Demo heartbeat on frozen contract. Numbers frozen: 5s interval, RED if no
 * fresh anchor after 12s (STALE_TIMEOUT_SEC=12). Worst-case detection =
 * interval + pipeline (~0.3s local), reported from 20-trial benchmark.
 *
 * Item 17: every cycle wrapped in try/catch(Throwable) - loop never dies silently.
 * Item 5: 1s watchdog flips dashboard to STALE even with zero requests.
 * Item 14: seq persisted in config/seq.dat.
 * Item 3: keys in keys/ (outside writable config/), see KeyStore.
 * Item 12: Boss re-read is "independent recompute, single-host only" - remote has signed measurement only.
 */
public final class Main {
    static final long INTERVAL_MS = 5000;
    static final long STALE_SEC = 12;

    public static void main(String[] args) throws Exception {
        Path bin = Paths.get("java/src/integrity/agent/AgentState.java");
        Path cfg = Paths.get("config/agent-config.json");
        Path base = Paths.get("config/baseline.json");
        String agentId = "agent-01";

        if (!Files.exists(base)) {
            System.out.println("No baseline, enrolling trusted golden...");
            Enroller.main(new String[]{bin.toString(), cfg.toString()});
        }
        Verifier.Baseline baseline = Verifier.loadBaseline(base);
        System.out.println("BASELINE hComb=" + baseline.hComb());
        if (baseline.publicKey().isEmpty())
            System.out.println("KEY PIN: not pinned (fresh-clone friendly). Run Enroller to pin the boss-trusted key and catch key swaps as KEY_MISMATCH.");
        else
            System.out.println("KEY PIN: pinned " + baseline.publicKey().substring(0, Math.min(16, baseline.publicKey().length())) + "... (key swap -> KEY_MISMATCH)");
        if (baseline.chainContract().isEmpty())
            System.out.println("CHAIN PIN: not pinned (run Enroller with config/chain.json present to pin contract+chainId).");
        else
            System.out.println("CHAIN PIN: " + baseline.chainContract() + " chainId=" + baseline.chainId());

        KeyPair kp = KeyStore.defaults().loadOrCreate();
        Signer signer = new Signer(kp.getPrivate());
        Verifier verifier = new Verifier(agentId, kp.getPublic(), baseline, STALE_SEC);
        Witness witness = new Witness();
        ChainAnchor anchor = new ChainAnchor("http://127.0.0.1:8545", baseline.chainContract(), baseline.chainId());
        SeqStore seqStore = new SeqStore(Paths.get("config/seq.dat"));
        Dashboard dash = new Dashboard();
        // Audit boot check: whole witness chain must verify (fresh file = vacuously ok).
        boolean[] witChainOk = { !Files.exists(witness.file()) || Witness.verify(witness.file(), witness.publicKey()) };
        dash.setWitness(new Dashboard.WitnessInfo(true, witChainOk[0], witness.lineCount(), witness.head(), 0, "-"));
        System.out.println("WITNESS chain=" + (witChainOk[0] ? "verified" : "BROKEN") + " entries=" + witness.lineCount()
                + (witChainOk[0] ? "" : " - audit trail failed verification"));
        HttpServer http = dash.start(8080);

        // Item 13 demo endpoint: simulated memory attack without file edit.
        http.createContext("/tamper/memory", ex -> {
            String q = ex.getRequestURI().getQuery();
            String v = "999";
            if (q != null && q.contains("limit=")) v = q.split("limit=")[1].split("&")[0];
            AgentState.setLimit(v);
            String r = "memory limit override=" + v + " (call /tamper/memory/clear to restore)";
            byte[] b = r.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            try (var o = ex.getResponseBody()) { o.write(b); }
        });
        http.createContext("/tamper/memory/clear", ex -> {
            AgentState.clearOverride();
            byte[] b = "cleared".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            try (var o = ex.getResponseBody()) { o.write(b); }
        });

        long seq = seqStore.load();
        String prevHash = baseline.hComb();
        // Resume chain tip from ledger fallback if present (best effort).
        try {
            var lines = Files.exists(Paths.get("ledger.jsonl")) ? Files.readAllLines(Paths.get("ledger.jsonl")) : java.util.List.<String>of();
            if (!lines.isEmpty()) {
                String last = lines.get(lines.size() - 1);
                String h = Verifier.get(last, "hComb");
                long s = Long.parseLong(Verifier.get(last, "seq"));
                if (h.length() == 64) { prevHash = h.toLowerCase(); seq = Math.max(seq, s + 1); }
            }
        } catch (Exception ignored) {}

        // Item 5: watchdog - 1s tick, STALE even when Checker dead / no requests.
        final long[] cycle = {0};
        final long[] seqBox = {seq};
        final boolean chainPinned = !baseline.chainContract().isEmpty();
        final String[] readbackBox = {"off"};
        final integrity.batch.BatchCollector batch = new integrity.batch.BatchCollector();
        final String[] batchRootBox = {"-"};
        final Dashboard.Status[] last = {new Dashboard.Status("STARTING", seq, "-", "BOOT",
                baseline.hComb(), "-", "-", "-", "-", "boot", 0, 0, 0, false, chainPinned, "off", "-")};
        Thread watchdog = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(1000);
                    long now = System.currentTimeMillis() / 1000;
                    if (verifier.isStale(now) && !"STALE".equals(last[0].state())) {
                        Dashboard.Status st = new Dashboard.Status("STALE", seqBox[0], "-", "STALE",
                                baseline.hComb(), "-", verifier.headHash(), verifier.headHash(),
                                "-", "STALE: no fresh anchor for >" + STALE_SEC + "s (checker killed?) head=" + verifier.headHash(), cycle[0], 0, 0, false, chainPinned, readbackBox[0], batchRootBox[0]);
                        last[0] = st;
                        dash.update(st);
                        System.out.println("WATCHDOG STALE head=" + verifier.headHash());
                    }
                } catch (Throwable t) { System.out.println("watchdog err: " + t); }
            }
        });
        watchdog.setDaemon(true);
        watchdog.start();

        System.out.println("TIMING frozen: interval 5s, stale after 12s. Worst-case detection ~= 5.3s local (see docs/BENCHMARKS.md).");
        while (true) {
            cycle[0]++;
            try {
                long ts = System.currentTimeMillis() / 1000;
                long t0 = System.nanoTime();
                Measurer.Measurement m = Measurer.measure(bin, cfg, AgentState.current());
                String sig = signer.sign(agentId, seq, ts, m.hBin(), m.hCfg(), m.hMem(), m.hComb(), prevHash);
                long t1 = System.nanoTime();
                var tmp = new SignedMeasurement(agentId, seq, ts, m.hBin(), m.hCfg(), m.hMem(), m.hComb(), prevHash, sig, "");
                var receipt = anchor.anchor(tmp);
                long effectiveTs = receipt.fromChain() && receipt.chainTs() > 0 ? receipt.chainTs() : ts;
                SignedMeasurement anchored = new SignedMeasurement(agentId, seq, ts, m.hBin(), m.hCfg(),
                        m.hMem(), m.hComb(), prevHash, sig, receipt.ledgerRef());
                Measurer.Measurement re = Measurer.measure(bin, cfg, AgentState.current());
                Verifier.Verdict v = verifier.check(re, anchored, effectiveTs, receipt.fromChain(), receipt.chainRec());
                long t2 = System.nanoTime();
                String rb = receipt.fromChain()
                        ? (receipt.chainRec() != null ? "ok" : "miss") : "off";
                readbackBox[0] = rb;
                String readback = "readback=" + rb;

                String state = v.ok() ? "GREEN" : "RED";
                String component = Verifier.diffHint(v.reason()).getOrDefault("component", "-");
                long measureMs = (t1 - t0) / 1_000_000;
                long verifyMs = (t2 - t1) / 1_000_000;
                // Boss counter-attestation: own key, own file, hash-chained.
                boolean witOk = witness.record(seq, ts, state, v.reason().name(), component, m.hComb(), prevHash);
                // Full chain re-verify about once a minute (O(file), cheap) so the
                // dashboard witness panel shows a live verification result, not a boot-time guess.
                if (cycle[0] % 12 == 1) witChainOk[0] = Witness.verify(witness.file(), witness.publicKey());
                dash.setWitness(new Dashboard.WitnessInfo(true, witChainOk[0], witness.lineCount(), witness.head(), seq, v.reason().name()));
                String detail = v.reason() + " " + v.detail()
                        + " | measure+sign " + measureMs + "ms anchor+verify " + verifyMs + "ms"
                        + " | witness=" + (witOk ? "ok" : "OFF")
                        + " " + readback
                        + " chainUp=" + receipt.fromChain() + (receipt.fromChain() ? " chainTs=" + effectiveTs : "");
                // Live Merkle batch window (docs/SCALING.md): every 12 successful
                // heartbeats -> one root + proofs, reported off-chain in status/detail.
                batch.add(agentId, m.hComb());
                if (batch.size() >= 12) {
                    long b0 = System.nanoTime();
                    String broot = batch.root();
                    int bproofs = batch.proofs().size();
                    long bUs = (System.nanoTime() - b0) / 1_000;
                    batch.clear();
                    batchRootBox[0] = broot;
                    detail += " | batch window=12 root=" + broot.substring(0, 8)
                            + " proofs=" + bproofs + " build=" + bUs + "us";
                    System.out.println("BATCH window=12 root=" + broot + " buildUs=" + bUs);
                }
                Dashboard.Status st = new Dashboard.Status(state, seq, component, v.reason().name(),
                        baseline.hComb(), re.hComb(),
                        m.hComb(), prevHash, receipt.ledgerRef(), detail, cycle[0], measureMs, verifyMs, receipt.fromChain(), chainPinned, rb, batchRootBox[0]);
                last[0] = st;
                dash.update(st);
                System.out.println("cycle=" + cycle[0] + " seq=" + seq + " " + state + " " + v.reason()
                        + " comp=" + component + " ledger=" + receipt.ledgerRef());
            prevHash = m.hComb();
            seq++;
            seqBox[0] = seq;
            seqStore.save(seq);
            } catch (Throwable t) {
                // Item 17: never let the loop die silently.
                System.out.println("CYCLE_ERR " + t);
                // Stall semantics: first 12s of errors = RED CYCLE_ERR (cause shown);
                // beyond the stale window the heartbeat is dead -> STALE (watchdog wins,
                // no flicker between CYCLE_ERR and STALE).
                Dashboard.Status st;
                if (verifier.isStale(System.currentTimeMillis() / 1000)) {
                    st = new Dashboard.Status("STALE", seq, "-", "STALE",
                            baseline.hComb(), "-", verifier.headHash(), verifier.headHash(), "-",
                            "STALE: heartbeat stalled >" + STALE_SEC + "s (cause: " + t + ") head=" + verifier.headHash(),
                            cycle[0], 0, 0, false, chainPinned, readbackBox[0], batchRootBox[0]);
                    System.out.println("WATCHDOG STALE (stalled loop) head=" + verifier.headHash());
                } else {
                    st = new Dashboard.Status("RED", seq, "-", "CYCLE_ERR",
                            baseline.hComb(), "ERR", prevHash, prevHash, "-",
                            "CYCLE_ERR: " + t + " (missing file counts as tamper)", cycle[0], 0, 0, false, chainPinned, readbackBox[0], batchRootBox[0]);
                }
                last[0] = st;
                dash.update(st);
                try { Thread.sleep(1000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
            }
            try { Thread.sleep(INTERVAL_MS); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); break; }
        }
    }
}
