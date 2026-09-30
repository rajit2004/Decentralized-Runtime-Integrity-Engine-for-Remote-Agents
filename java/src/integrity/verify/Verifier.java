package integrity.verify;

import integrity.measure.Measurer;
import integrity.measure.SignedMeasurement;
import integrity.sign.Signer;
import java.nio.file.*;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * Judge-proof verifier on frozen contract.
 * Loads full golden baseline (hBin/hCfg/hMem/hComb) once, immutable.
 * Boss independently re-measures, then:
 *  1 sig over agentId|seq|ts|hBin|hCfg|hMem|hComb|prevHash
 *  2 H_re components == reported components (catches lying Checker, tells WHICH changed)
 *  3 reported == baseline (tells which golden component broke)
 *  4 hComb == SHA256(raws) both sides, seq monotonic, ts fresh, prevHash chain intact
 */
public final class Verifier {
    public enum Reason {
        OK,
        SIG_FAIL, MEASURE_MISMATCH_BIN, MEASURE_MISMATCH_CFG, MEASURE_MISMATCH_MEM,
        POLICY_BIN_CHANGED, POLICY_CFG_CHANGED, POLICY_MEM_CHANGED,
        COMB_MISMATCH, PREV_HASH_BREAK, STALE_REPLAY
    }

    public record Verdict(Reason reason, String expected, String observed, String detail) {
        public boolean ok() { return reason == Reason.OK; }
    }

    public record Baseline(String agentId, String hBin, String hCfg, String hMem, String hComb) {}

    private final String agentId;
    private final PublicKey pub;
    private final Baseline base;
    private long lastSeq = 0; // genesis seq 0 enrolled, first live seq must be 1
    private String expectedPrev;
    private final long staleSec;
    private boolean first = true;
    // Item 5 watchdog + item 10 headHash: tamper-evident ledger cursor.
    // headHash remembers last accepted hComb; a rewritten file ledger with
    // recomputed hashes still breaks prevHash linkage against this memory.
    private volatile long lastFreshWallSec = System.currentTimeMillis() / 1000;
    private volatile String headHash;

    public Verifier(String agentId, PublicKey pub, Baseline base, long staleSec) {
        this.agentId = agentId; this.pub = pub; this.base = base; this.staleSec = staleSec;
        this.expectedPrev = base.hComb();
        this.headHash = base.hComb();
    }

    /** Item 5/10: watchdog cursor. Call on every accepted-or-policy measurement. */
    public void noteFresh(long wallSec, String hComb) {
        lastFreshWallSec = wallSec;
        headHash = hComb;
    }

    public boolean isStale(long nowSec) { return (nowSec - lastFreshWallSec) > staleSec; }
    public String headHash() { return headHash; }
    public long lastFresh() { return lastFreshWallSec; }

    public static String get(String json, String key) {
        String k = "\"" + key + "\"";
        int i = json.indexOf(k);
        int c = json.indexOf(':', i);
        int v1 = json.indexOf('"', c);
        if (v1 < 0) { // numeric
            int s = c + 1;
            while (s < json.length() && (json.charAt(s) == ' ')) s++;
            int e = s;
            while (e < json.length() && "-0123456789".indexOf(json.charAt(e)) >= 0) e++;
            return json.substring(s, e).trim();
        }
        int v2 = json.indexOf('"', v1 + 1);
        return json.substring(v1 + 1, v2);
    }

    public static Baseline loadBaseline(Path p) throws Exception {
        String s = Files.readString(p);
        return new Baseline(get(s, "agentId"), get(s, "hBin").toLowerCase(),
                get(s, "hCfg").toLowerCase(), get(s, "hMem").toLowerCase(), get(s, "hComb").toLowerCase());
    }

    /** Full check. re = Boss independent measurement (demo only — remote has signed measurement only), m = reported. */
    public Verdict check(Measurer.Measurement re, SignedMeasurement m) throws Exception {
        return check(re, m, m.ts(), false);
    }

    /**
     * Item 8: effectiveTs = chain block.timestamp when fromChain, else Checker ts.
     * A compromised Checker can lie about ts; chain time is authoritative.
     */
    public Verdict check(Measurer.Measurement re, SignedMeasurement m, long effectiveTs, boolean fromChain) throws Exception {
        long now = System.currentTimeMillis() / 1000;
        long refTs = fromChain ? effectiveTs : m.ts();
        if (Math.abs(now - refTs) > staleSec) return new Verdict(Reason.STALE_REPLAY, "fresh-ts", Long.toString(refTs), "stale timestamp (chain-authoritative=" + fromChain + ")");
        if (!first && m.seq() <= lastSeq) return new Verdict(Reason.STALE_REPLAY, "seq>" + lastSeq, "seq=" + m.seq(), "replay or reorder");

        // 1. comb integrity both sides (raw-bytes rule)
        String recombReported;
        try { recombReported = Measurer.combine(m.hBin(), m.hCfg(), m.hMem()); }
        catch (Exception e) { return new Verdict(Reason.COMB_MISMATCH, "valid-hex", "bad-hex", "reported hashes not hex"); }
        if (!recombReported.equalsIgnoreCase(m.hComb()))
            return new Verdict(Reason.COMB_MISMATCH, recombReported, m.hComb(), "reported hComb != SHA256(raws)");
        String recombRe = Measurer.combine(re.hBin(), re.hCfg(), re.hMem());
        if (!recombRe.equalsIgnoreCase(re.hComb()))
            return new Verdict(Reason.COMB_MISMATCH, recombRe, re.hComb(), "recomputed comb broken");

        // 2. signature over FULL payload
        boolean sigOk = Signer.verify(pub, m.agentId(), m.seq(), m.ts(),
                m.hBin(), m.hCfg(), m.hMem(), m.hComb(), m.prevHash(), m.sig());
        if (!sigOk) return new Verdict(Reason.SIG_FAIL, "valid-sig", "bad-sig", "seal invalid over full payload");

        // 3. prevHash chain (genesis prev = baseline hComb or zeros on very first cycle)
        if (!first && !m.prevHash().equalsIgnoreCase(expectedPrev))
            return new Verdict(Reason.PREV_HASH_BREAK, expectedPrev, m.prevHash(), "hash chain break: missing or forked cycle");
        if (first && !(m.prevHash().equalsIgnoreCase(expectedPrev) || m.prevHash().equalsIgnoreCase(Measurer.ZERO_HASH)))
            return new Verdict(Reason.PREV_HASH_BREAK, expectedPrev, m.prevHash(), "genesis prev must be baseline hComb or zeros");

        // 4. Boss independent re-measure vs reported — tells WHICH component Checker misreported
        if (!re.hBin().equalsIgnoreCase(m.hBin()))
            return new Verdict(Reason.MEASURE_MISMATCH_BIN, m.hBin(), re.hBin(), "BINARY diverge: checker lied or MITM");
        if (!re.hCfg().equalsIgnoreCase(m.hCfg()))
            return new Verdict(Reason.MEASURE_MISMATCH_CFG, m.hCfg(), re.hCfg(), "CONFIG diverge: checker lied or MITM");
        if (!re.hMem().equalsIgnoreCase(m.hMem()))
            return new Verdict(Reason.MEASURE_MISMATCH_MEM, m.hMem(), re.hMem(), "MEMORY diverge: checker lied or MITM");

        // 5. reported vs golden baseline — tells WHICH golden component broke.
        // Chain linkage already verified, so advance chain cursor even on POLICY fail:
        // sustained tamper must stay POLICY_* (not flip to PREV_HASH_BREAK).
        if (!m.hBin().equalsIgnoreCase(base.hBin())) {
            lastSeq = m.seq(); expectedPrev = m.hComb(); first = false;
            noteFresh(System.currentTimeMillis() / 1000, m.hComb());
            return new Verdict(Reason.POLICY_BIN_CHANGED, base.hBin(), m.hBin(), "BINARY changed vs golden baseline");
        }
        if (!m.hCfg().equalsIgnoreCase(base.hCfg())) {
            lastSeq = m.seq(); expectedPrev = m.hComb(); first = false;
            noteFresh(System.currentTimeMillis() / 1000, m.hComb());
            return new Verdict(Reason.POLICY_CFG_CHANGED, base.hCfg(), m.hCfg(), "CONFIG changed vs golden baseline");
        }
        if (!m.hMem().equalsIgnoreCase(base.hMem())) {
            lastSeq = m.seq(); expectedPrev = m.hComb(); first = false;
            noteFresh(System.currentTimeMillis() / 1000, m.hComb());
            return new Verdict(Reason.POLICY_MEM_CHANGED, base.hMem(), m.hMem(), "MEMORY changed vs golden baseline");
        }

        lastSeq = m.seq();
        expectedPrev = m.hComb();
        first = false;
        noteFresh(System.currentTimeMillis() / 1000, m.hComb());
        return new Verdict(Reason.OK, base.hComb(), re.hComb(), "sig+measure+baseline+chain all pass seq=" + m.seq());
    }

    public static Map<String, String> diffHint(Reason r) {
        Map<String, String> m = new HashMap<>();
        m.put("component", switch (r) {
            case POLICY_BIN_CHANGED, MEASURE_MISMATCH_BIN -> "binary";
            case POLICY_CFG_CHANGED, MEASURE_MISMATCH_CFG -> "config";
            case POLICY_MEM_CHANGED, MEASURE_MISMATCH_MEM -> "memory";
            default -> "-";
        });
        return m;
    }
}
