package integrity.batch;

import integrity.agent.AgentState;
import integrity.measure.Measurer;
import integrity.sign.Signer;
import integrity.verify.Verifier;
import java.nio.file.*;
import java.security.KeyPair;
import java.util.*;

/**
 * Item 4: 20-trial pipeline timing. Headline reworded from "RED in <5s" to
 * "interval 5s, pipeline avg/worst below, STALE after 12s".
 * Run: java -cp out integrity.batch.Bench20
 */
public final class Bench20 {
    public static void main(String[] args) throws Exception {
        Path bin = Paths.get("java/src/integrity/agent/AgentState.java");
        Path cfg = Paths.get("config/agent-config.json");
        KeyPair kp = Signer.generate();
        Signer signer = new Signer(kp.getPrivate());
        List<Long> measures = new ArrayList<>(), signs = new ArrayList<>(), verifies = new ArrayList<>();
        String prev = Measurer.ZERO_HASH;
        Verifier.Baseline base = new Verifier.Baseline("agent-01", "a", "b", "c", "d", "");
        // enroll real baseline for combine validity
        Measurer.Measurement m0 = Measurer.measure(bin, cfg, AgentState.current());
        base = new Verifier.Baseline("agent-01", m0.hBin(), m0.hCfg(), m0.hMem(), m0.hComb(), "");
        Verifier v = new Verifier("agent-01", kp.getPublic(), base, 12);
        for (int i = 1; i <= 20; i++) {
            long t0 = System.nanoTime();
            Measurer.Measurement m = Measurer.measure(bin, cfg, AgentState.current());
            long t1 = System.nanoTime();
            String sig = signer.sign("agent-01", i, System.currentTimeMillis() / 1000,
                    m.hBin(), m.hCfg(), m.hMem(), m.hComb(), prev);
            long t2 = System.nanoTime();
            var sm = new integrity.measure.SignedMeasurement("agent-01", i,
                    System.currentTimeMillis() / 1000, m.hBin(), m.hCfg(), m.hMem(), m.hComb(), prev, sig, "bench");
            Measurer.Measurement re = Measurer.measure(bin, cfg, AgentState.current());
            // fresh verifier per trial would reset chain; reuse v but first trial prev=ZERO handling:
            // use standalone timing of verify call
            long t3 = System.nanoTime();
            v.check(re, sm, sm.ts(), false);
            long t4 = System.nanoTime();
            measures.add((t1 - t0) / 1_000_000); signs.add((t2 - t1) / 1_000_000); verifies.add((t4 - t3) / 1_000_000);
            prev = m.hComb();
            System.out.println("trial=" + i + " measure=" + measures.get(measures.size()-1) + "ms sign=" + signs.get(signs.size()-1) + "ms verify=" + verifies.get(verifies.size()-1) + "ms");
        }
        System.out.println("AVG measure=" + avg(measures) + "ms worst=" + max(measures) + "ms");
        System.out.println("AVG sign=" + avg(signs) + "ms worst=" + max(signs) + "ms");
        System.out.println("AVG verify=" + avg(verifies) + "ms worst=" + max(verifies) + "ms");
        long pipeAvg = (long)(avg(measures) + avg(signs) + avg(verifies));
        long pipeWorst = max(measures) + max(signs) + max(verifies);
        System.out.println("PIPELINE avg=" + pipeAvg + "ms worst=" + pipeWorst + "ms (+5s interval => worst detection ~" + (5000 + pipeWorst) + "ms, STALE after 12s)");
    }

    static double avg(List<Long> l) { return l.stream().mapToLong(x -> x).average().orElse(0); }
    static long max(List<Long> l) { return l.stream().mapToLong(x -> x).max().orElse(0); }
}
