package integrity;

import integrity.agent.AgentState;
import integrity.chain.ChainAnchor;
import integrity.enroll.Enroller;
import integrity.measure.Measurer;
import integrity.measure.SignedMeasurement;
import integrity.sign.Signer;
import integrity.ui.Dashboard;
import integrity.verify.Verifier;
import java.nio.file.*;
import java.security.KeyPair;

/**
 * Demo heartbeat on frozen contract.
 * seq starts at 1 (0 = genesis baseline), prevHash chains hComb.
 * Loop: measure -> sign(full payload) -> anchor(JSON) -> re-measure -> 4-family verify -> dashboard.
 * Tamper test: edit config/agent-config.json live -> RED POLICY_CFG_CHANGED with component name.
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
        Verifier.Baseline baseline = Verifier.loadBaseline(base);
        System.out.println("BASELINE hComb=" + baseline.hComb());

        KeyPair kp = Signer.generate(); // demo ephemeral; prod: HSM/disk
        Signer signer = new Signer(kp.getPrivate());
        Verifier verifier = new Verifier(agentId, kp.getPublic(), baseline, 30);
        ChainAnchor anchor = new ChainAnchor("http://127.0.0.1:8545");
        Dashboard dash = new Dashboard();
        dash.start(8080);

        long seq = 1;
        String prevHash = baseline.hComb(); // chain from golden; first cycle may also accept zeros
        long cycle = 0;
        while (true) {
            cycle++;
            long ts = System.currentTimeMillis() / 1000;
            long t0 = System.nanoTime();
            Measurer.Measurement m = Measurer.measure(bin, cfg, AgentState.current());
            String sig = signer.sign(agentId, seq, ts, m.hBin(), m.hCfg(), m.hMem(), m.hComb(), prevHash);
            long t1 = System.nanoTime();
            // anchor full JSON, get ledgerRef
            var tmp = new SignedMeasurement(agentId, seq, ts, m.hBin(), m.hCfg(), m.hMem(), m.hComb(), prevHash, sig, "");
            var receipt = anchor.anchor(tmp);
            SignedMeasurement anchored = new SignedMeasurement(agentId, seq, ts, m.hBin(), m.hCfg(),
                    m.hMem(), m.hComb(), prevHash, sig, receipt.ledgerRef());
            Measurer.Measurement re = Measurer.measure(bin, cfg, AgentState.current());
            Verifier.Verdict v = verifier.check(re, anchored);
            long t2 = System.nanoTime();

            String state = v.ok() ? "GREEN" : "RED";
            String component = Verifier.diffHint(v.reason()).getOrDefault("component", "-");
            String detail = v.reason() + " " + v.detail()
                    + " | measure " + ((t1 - t0) / 1_000_000) + "ms verify " + ((t2 - t1) / 1_000_000) + "ms"
                    + " chainUp=" + receipt.fromChain();
            dash.update(new Dashboard.Status(state, seq, component, baseline.hComb(), re.hComb(),
                    m.hComb(), prevHash, receipt.ledgerRef(), detail, cycle));
            System.out.println("cycle=" + cycle + " seq=" + seq + " " + state + " " + v.reason()
                    + " comp=" + component + " expected=" + baseline.hComb().substring(0, 12)
                    + " observed=" + re.hComb().substring(0, 12) + " ledger=" + receipt.ledgerRef());
            // Frozen: prevHash = previous measurement hComb (even if tampered) keeps hash chain live.
            prevHash = m.hComb();
            seq++;
            Thread.sleep(5000);
        }
    }
}
