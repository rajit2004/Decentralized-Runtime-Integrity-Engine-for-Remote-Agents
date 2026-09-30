package integrity.verify;

import integrity.sign.Signer;
import java.nio.file.*;
import java.security.PublicKey;

/**
 * Judge-proof verifier. Needs BOTH chain timeline AND baseline goodness.
 * Loads baseline.json once at startup (immutable), never updates from chain.
 */
public final class Verifier {
    public enum Reason { OK, SIG_FAIL, MEASURE_MISMATCH, POLICY_MISMATCH, STALE_REPLAY }

    public record Verdict(Reason reason, String expected, String observed, String detail) {
        public boolean ok() { return reason == Reason.OK; }
    }

    private final String agentId;
    private final PublicKey pub;
    private final String hBase;
    private long lastNonce = -1;
    private final long staleSec;

    public Verifier(String agentId, PublicKey pub, String hBase, long staleSec) {
        this.agentId = agentId; this.pub = pub; this.hBase = hBase; this.staleSec = staleSec;
    }

    public static String loadBaselineHComb(Path baselineJson) throws Exception {
        String s = Files.readString(baselineJson);
        // minimal parse: "hComb":"<hex>"
        int i = s.indexOf("\"hComb\"");
        int q1 = s.indexOf('"', i + 7) + 1;
        // find value start
        int c = s.indexOf(':', i); int v1 = s.indexOf('"', c) + 1; int v2 = s.indexOf('"', v1);
        return s.substring(v1, v2);
    }

    /**
     * @param hRe recomputed by Boss independent read
     * @param hChain latest hash from chain/fallback
     */
    public Verdict check(String hRe, String hChain, long ts, long nonce, String sigB64) throws Exception {
        long now = System.currentTimeMillis() / 1000;
        if (Math.abs(now - ts) > staleSec || nonce <= lastNonce) {
            // allow first run: lastNonce=-1, so nonce 0 passes
            if (!(lastNonce == -1 && nonce == 0)) {
                if (nonce <= lastNonce || Math.abs(now - ts) > staleSec)
                    return new Verdict(Reason.STALE_REPLAY, Long.toString(lastNonce), Long.toString(nonce), "stale or replay");
            }
        }
        boolean sigOk = Signer.verify(pub, agentId, hChain, ts, nonce, sigB64);
        if (!sigOk) return new Verdict(Reason.SIG_FAIL, "valid-sig", "bad-sig", "seal invalid");
        if (!hRe.equals(hChain))
            return new Verdict(Reason.MEASURE_MISMATCH, hChain, hRe, "checker lied or MITM: boss sees different");
        if (!hRe.equals(hBase) || !hChain.equals(hBase))
            return new Verdict(Reason.POLICY_MISMATCH, hBase, hRe, "edited vs golden baseline");
        lastNonce = nonce;
        return new Verdict(Reason.OK, hBase, hRe, "all 4 checks pass");
    }
}
