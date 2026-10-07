package integrity.enroll;

import integrity.measure.Measurer;
import integrity.sign.KeyStore;
import java.nio.file.*;
import java.security.KeyPair;
import java.util.Map;

/**
 * Phase 0 trusted enrollment. Run once in clean room.
 * Captures golden hBin/hCfg/hMem/hComb into config/baseline.json (Boss trusted store)
 * and pins the boss-trusted public key, so a later key swap on the agent box
 * fails as KEY_MISMATCH instead of self-verifying into GREEN.
 * Frozen contract: hComb = SHA256(raw32||raw32||raw32).
 * Usage: java -cp out integrity.enroll.Enroller <binPath> <cfgPath>
 */
public final class Enroller {
    public static void main(String[] args) throws Exception {
        Path bin = Paths.get(args.length > 0 ? args[0] : "java/src/integrity/agent/AgentState.java");
        Path cfg = Paths.get(args.length > 1 ? args[1] : "config/agent-config.json");
        Map<String, String> state = integrity.agent.AgentState.current();
        Measurer.Measurement m = Measurer.measure(bin, cfg, state);
        KeyPair kp = KeyStore.defaults().loadOrCreate();
        String pin = "";
        String chainAddr = "", chainId = "";
        Path chainCfg = Paths.get("config/chain.json");
        if (Files.exists(chainCfg)) {
            String s = Files.readString(chainCfg);
            chainAddr = integrity.verify.Verifier.get(s, "contractAddr");
            chainId = integrity.verify.Verifier.get(s, "chainId");
            if (!chainAddr.isBlank())
                pin = ",\"chainContract\":\"" + chainAddr + "\",\"chainId\":\"" + chainId + "\"";
        }
        String json = "{\"agentId\":\"agent-01\",\"seq\":0,\"ts\":" + (System.currentTimeMillis() / 1000)
                + ",\"hBin\":\"" + m.hBin() + "\",\"hCfg\":\"" + m.hCfg()
                + "\",\"hMem\":\"" + m.hMem() + "\",\"hComb\":\"" + m.hComb()
                + "\",\"prevHash\":\"" + Measurer.ZERO_HASH
                + "\",\"publicKey\":\"" + KeyStore.pubB64(kp.getPublic()) + "\"" + pin + "}";
        Files.createDirectories(Paths.get("config"));
        Files.writeString(Paths.get("config/baseline.json"), json);
        System.out.println("BASELINE_ENROLLED hComb=" + m.hComb());
        System.out.println("KEY PINNED " + KeyStore.pubB64(kp.getPublic()).substring(0, 16) + "... (key swap now fails as KEY_MISMATCH)");
        if (!pin.isEmpty())
            System.out.println("CHAIN PINNED " + chainAddr + " chainId=" + chainId + " (mismatch -> ledger fallback)");
        else
            System.out.println("CHAIN PIN: no config/chain.json, contract pin left open (fresh-clone friendly).");
        System.out.println("Wrote config/baseline.json - copy this to Boss, never overwrite from chain.");
    }
}
