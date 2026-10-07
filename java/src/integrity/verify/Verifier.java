package integrity.verify;

import integrity.chain.Abi;
import integrity.measure.Measurer;
import integrity.measure.SignedMeasurement;
import integrity.sign.KeyStore;
import integrity.sign.Signer;
import java.nio.file.*;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Judge-proof verifier on frozen contract.
 * Loads full golden baseline (hBin/hCfg/hMem/hComb) once, immutable.
 * Boss independently re-measures, then:
 *  0 key on disk == key pinned at enrollment (catches key-swap attacks)
 *  1 sig over agentId|seq|ts|hBin|hCfg|hMem|hComb|prevHash
 *  2 H_re components == reported components (catches lying Checker, tells WHICH changed)
 *  3 reported == baseline (tells which golden component broke)
 *  4 hComb == SHA256(raws) both sides, seq monotonic, ts fresh, prevHash chain intact
 */
public final class Verifier {
    public enum Reason {
        OK,
        KEY_MISMATCH,
        SIG_FAIL, MEASURE_MISMATCH_BIN, MEASURE_MISMATCH_CFG, MEASURE_MISMATCH_MEM,
        POLICY_BIN_CHANGED, POLICY_CFG_CHANGED, POLICY_MEM_CHANGED,
        COMB_MISMATCH, PREV_HASH_BREAK, STALE_REPLAY, CHAIN_MISMATCH
    }

    public record Verdict(Reason reason, String expected, String observed, String detail) {
        public boolean ok() { return reason == Reason.OK; }
    }

    public record Baseline(String agentId, String hBin, String hCfg, String hMem, String hComb, String publicKey) {}

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

    /** Item 5/10: watchdog cursor. Call on every authentic linked measurement. */
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
        if (i < 0) return "";
        int c = json.indexOf(':', i);
        if (c < 0) return "";
        int s = c + 1;
        while (s < json.length() && json.charAt(s) == ' ') s++;
        // Numeric values are unquoted in our JSON. The old "look for any quote
        // after the colon" heuristic returned the NEXT key's name instead of the
        // number whenever more quoted fields followed (broke seq resume + witness).
        if (s < json.length() && (Character.isDigit(json.charAt(s)) || json.charAt(s) == '-')) {
            int e = s;
            while (e < json.length() && "-0123456789".indexOf(json.charAt(e)) >= 0) e++;
            return json.substring(s, e);
        }
        int v1 = json.indexOf('"', s);
        if (v1 < 0) return "";
        int v2 = json.indexOf('"', v1 + 1);
        if (v2 < 0) return "";
        return json.substring(v1 + 1, v2);
    }

    public static Baseline loadBaseline(Path p) throws Exception {
        String s = Files.readString(p);
        String pinned = s.contains("\"publicKey\"") ? get(s, "publicKey") : "";
        return new Baseline(get(s, "agentId"), get(s, "hBin").toLowerCase(),
                get(s, "hCfg").toLowerCase(), get(s, "hMem").toLowerCase(), get(s, "hComb").toLowerCase(),
                pinned);
    }

    /** Full check. re = Boss independent measurement (demo only - remote has signed measurement only), m = reported. */
    public Verdict check(Measurer.Measurement re, SignedMeasurement m) throws Exception {
        return check(re, m, m.ts(), false, null);
    }

    public Verdict check(Measurer.Measurement re, SignedMeasurement m, long effectiveTs, boolean fromChain) throws Exception {
        return check(re, m, effectiveTs, fromChain, null);
    }

    /**
     * Item 8: effectiveTs = chain block.timestamp when fromChain, else Checker ts.
     * A compromised Checker can lie about ts; chain time is authoritative.
     * chainRec = on-chain getLatest readback of this submission (null = no readback).
     */
    public Verdict check(Measurer.Measurement re, SignedMeasurement m, long effectiveTs, boolean fromChain,
                         Abi.ChainRecord chainRec) throws Exception {
        long now = System.currentTimeMillis() / 1000;
        // 0. Identity first: the key on disk must be the one enrolled at Phase 0.
        // A swapped key pair would otherwise self-verify into GREEN. Pin lives in
        // the Boss-trusted baseline, so the attacker must rewrite the baseline too.
        if (!base.publicKey().isEmpty()) {
            String diskB64 = KeyStore.pubB64(pub);
            if (!diskB64.equals(base.publicKey()))
                return new Verdict(Reason.KEY_MISMATCH, base.publicKey(), diskB64,
                        "signing key replaced since enrollment (key-swap attack)");
        }
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

        // The report is authentic, fresh, monotonic and linked: it enters the
        // chain NOW. Verdicts below judge state, not linkage, so a mid-cycle
        // change (MEASURE_MISMATCH_*) or sustained tamper stays itself instead
        // of flipping every later cycle into PREV_HASH_BREAK. Matches Main's
        // per-cycle cursor advance and the contract's prevHash linkage rule.
        lastSeq = m.seq();
        expectedPrev = m.hComb();
        first = false;
        noteFresh(now, m.hComb());

        // 3b. authoritative chain readback: what the chain STORED must equal what
        // we submitted. Catches wrong-contract redirects, reorgs, decode/RPC lies.
        if (fromChain && chainRec != null && !matchesChain(m, chainRec))
            return new Verdict(Reason.CHAIN_MISMATCH,
                    "seq=" + m.seq() + " hComb=" + m.hComb().substring(0, 16),
                    "seq=" + chainRec.seq() + " hComb=" + chainRec.hComb().substring(0, 16),
                    "on-chain record differs from submitted measurement");

        // 4. Boss independent re-measure vs reported - tells WHICH component Checker misreported
        if (!re.hBin().equalsIgnoreCase(m.hBin()))
            return new Verdict(Reason.MEASURE_MISMATCH_BIN, m.hBin(), re.hBin(), "BINARY diverge: checker lied or MITM");
        if (!re.hCfg().equalsIgnoreCase(m.hCfg()))
            return new Verdict(Reason.MEASURE_MISMATCH_CFG, m.hCfg(), re.hCfg(), "CONFIG diverge: checker lied or MITM");
        if (!re.hMem().equalsIgnoreCase(m.hMem()))
            return new Verdict(Reason.MEASURE_MISMATCH_MEM, m.hMem(), re.hMem(), "MEMORY diverge: checker lied or MITM");

        // 5. reported vs golden baseline - tells WHICH golden component broke.
        if (!m.hBin().equalsIgnoreCase(base.hBin()))
            return new Verdict(Reason.POLICY_BIN_CHANGED, base.hBin(), m.hBin(), "BINARY changed vs golden baseline");
        if (!m.hCfg().equalsIgnoreCase(base.hCfg()))
            return new Verdict(Reason.POLICY_CFG_CHANGED, base.hCfg(), m.hCfg(), "CONFIG changed vs golden baseline");
        if (!m.hMem().equalsIgnoreCase(base.hMem()))
            return new Verdict(Reason.POLICY_MEM_CHANGED, base.hMem(), m.hMem(), "MEMORY changed vs golden baseline");

        return new Verdict(Reason.OK, base.hComb(), re.hComb(), "sig+measure+baseline+chain all pass seq=" + m.seq());
    }

    /** Submitted measurement vs on-chain getLatest record (sig compared as raw bytes). */
    public static boolean matchesChain(SignedMeasurement m, Abi.ChainRecord c) {
        if (c == null) return false;
        try {
            return m.seq() == c.seq()
                    && m.hBin().equalsIgnoreCase(c.hBin())
                    && m.hCfg().equalsIgnoreCase(c.hCfg())
                    && m.hMem().equalsIgnoreCase(c.hMem())
                    && m.hComb().equalsIgnoreCase(c.hComb())
                    && m.prevHash().equalsIgnoreCase(c.prevHash())
                    && Arrays.equals(Base64.getDecoder().decode(m.sig()), c.sig());
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    public static Map<String, String> diffHint(Reason r) {
        Map<String, String> m = new HashMap<>();
        m.put("component", switch (r) {
            case POLICY_BIN_CHANGED, MEASURE_MISMATCH_BIN -> "binary";
            case POLICY_CFG_CHANGED, MEASURE_MISMATCH_CFG -> "config";
            case POLICY_MEM_CHANGED, MEASURE_MISMATCH_MEM -> "memory";
            case KEY_MISMATCH -> "key";
            case CHAIN_MISMATCH -> "chain";
            default -> "-";
        });
        return m;
    }
}
