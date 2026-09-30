package integrity.enroll;

import integrity.measure.Measurer;
import java.nio.file.*;
import java.util.Map;

/**
 * Phase 0 trusted enrollment. Run once in clean room.
 * Captures golden H_comb into config/baseline.json (Boss trusted store).
 * Usage: java -cp out integrity.enroll.Enroller <binPath> <cfgPath>
 */
public final class Enroller {
    public static void main(String[] args) throws Exception {
        Path bin = Paths.get(args.length > 0 ? args[0] : "java/src/integrity/agent/AgentState.java");
        Path cfg = Paths.get(args.length > 1 ? args[1] : "config/agent-config.json");
        // Canonical demo state — must match AgentState.current()
        Map<String, String> state = integrity.agent.AgentState.current();
        Measurer.Measurement m = Measurer.measure(bin, cfg, state);
        String json = "{\"agentId\":\"agent-01\",\"hBin\":\"" + m.hBin() + "\",\"hCfg\":\"" + m.hCfg()
                + "\",\"hMem\":\"" + m.hMem() + "\",\"hComb\":\"" + m.hComb() + "\"}";
        Files.createDirectories(Paths.get("config"));
        Files.writeString(Paths.get("config/baseline.json"), json);
        System.out.println("BASELINE_ENROLLED hComb=" + m.hComb());
        System.out.println("Wrote config/baseline.json — copy this to Boss, never overwrite from chain.");
    }
}
