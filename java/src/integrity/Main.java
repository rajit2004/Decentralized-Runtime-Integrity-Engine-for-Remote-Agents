package integrity;

import integrity.agent.AgentState;
import integrity.chain.ChainAnchor;
import integrity.enroll.Enroller;
import integrity.measure.Measurer;
import integrity.sign.Signer;
import integrity.ui.Dashboard;
import integrity.verify.Verifier;
import java.nio.file.*;
import java.security.KeyPair;
import java.util.Map;

/**
 * Demo heartbeat. Simulates remote Checker + local Boss in one JVM
 * but with INDEPENDENT reads (two measure calls) + immutable baseline.
 *
 * Life: enroll (if missing) -> loop { measure -> sign -> anchor -> re-measure -> 4-check verify -> dashboard }
 * Tamper test: edit config/agent-config.json live -> next cycle RED POLICY_MISMATCH.
 */
public final class Main {
    public static void main(String[] args) throws Exception {
        Path bin = Paths.get("java/src/integrity/agent/AgentState.java");
        Path cfg = Paths.get("config/agent-config.json");
        Path base = Paths.get("config/baseline.json");
        String agentId = "agent-01";

        if (!Files.exists(base)) {
            System.out.println("No baseline, enrolling trusted golden...");
            Enroller.main(new String[]{bin.toString(), cfg.toString()});
        }
        String hBase = Verifier.loadBaselineHComb(base);
        System.out.println("BASELINE hComb=" + hBase);

        KeyPair kp = Signer.generate(); // demo ephemeral; prod: load from HSM/disk
        Signer signer = new Signer(kp.getPrivate());
        Verifier verifier = new Verifier(agentId, kp.getPublic(), hBase, 30);
        ChainAnchor anchor = new ChainAnchor("http://127.0.0.1:8545");
        Dashboard dash = new Dashboard();
        dash.start(8080);

        long nonce = 0;
        long cycle = 0;
        while (true) {
            cycle++;
            long ts = System.currentTimeMillis() / 1000;
            long t0 = System.nanoTime();
            // Checker side: what remote sees
            Measurer.Measurement m = Measurer.measure(bin, cfg, AgentState.current());
            String sig = signer.sign(agentId, m.hComb(), ts, nonce);
            long t1 = System.nanoTime();
            var receipt = anchor.anchor(agentId, m.hComb(), nonce, sig);
            // Boss side: INDEPENDENT re-read (catches lying Checker)
            Measurer.Measurement re = Measurer.measure(bin, cfg, AgentState.current());
            Verifier.Verdict v = verifier.check(re.hComb(), m.hComb(), ts, nonce, sig);
            long t2 = System.nanoTime();

            String state = v.ok() ? "GREEN" : "RED";
            String detail = v.reason() + " " + v.detail()
                    + " | measure " + ((t1 - t0) / 1_000_000) + "ms verify " + ((t2 - t1) / 1_000_000) + "ms"
                    + " chainUp=" + receipt.fromChain();
            dash.update(new Dashboard.Status(state, hBase, re.hComb(), m.hComb(), receipt.txHash(), detail, cycle));
            System.out.println("cycle=" + cycle + " " + state + " " + v.reason()
                    + " expected=" + hBase.substring(0, 12) + " observed=" + re.hComb().substring(0, 12)
                    + " tx=" + receipt.txHash() + " nonce=" + nonce);
            nonce++;
            Thread.sleep(5000);
        }
    }
}
