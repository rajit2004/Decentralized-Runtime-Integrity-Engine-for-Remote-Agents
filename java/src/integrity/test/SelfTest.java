package integrity.test;

import integrity.agent.AgentState;
import integrity.chain.Abi;
import integrity.chain.ChainAnchor;
import integrity.chain.Keccak;
import integrity.batch.MerkleTree;
import integrity.enroll.SeqStore;
import integrity.measure.Measurer;
import integrity.measure.SignedMeasurement;
import integrity.sign.KeyStore;
import integrity.sign.Signer;
import integrity.verify.Verifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.KeyPair;
import java.util.*;

/**
 * One-command regression suite: asserts the frozen contract, every verdict in
 * the attack table, crypto vectors (cross-checked against ethers), Merkle scale,
 * and seq persistence. JDK-only, no HTTP, no port, temp files only.
 *
 *   javac -d out (Get-ChildItem -Recurse java/src/*.java)
 *   java -cp out integrity.test.SelfTest     (exit code 0 = all pass)
 *
 * CI runs this on every commit; also a live credibility prop ("watch it verify itself").
 */
public final class SelfTest {
    static int pass = 0, fail = 0;

    static void check(String name, boolean cond) {
        if (cond) { pass++; System.out.println("  PASS  " + name); }
        else      { fail++; System.out.println("  FAIL  " + name); }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("== Integrity SelfTest ==");

        keccakVectors();
        signerRoundtrip();
        rawBytesRule();
        attackTable();
        sustainedTamperStaysPolicy();
        keyPinning();
        witnessChain();
        dashboardWitnessJson();
        merkleScale();
        abiEncoding();
        chainReceipt();
        seqPersistence();

        System.out.println();
        System.out.println(fail == 0
                ? "ALL PASS (" + pass + " checks)"
                : "FAILED: " + fail + " of " + (pass + fail) + " checks");
        System.exit(fail == 0 ? 0 : 1);
    }

    // ---- crypto vectors (verified against ethers v6 keccak256) ----

    static void keccakVectors() {
        System.out.println("[keccak]");
        check("keccak256(\"\")",
                Keccak.keccak256Hex(new byte[0]).equals("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"));
        check("keccak256(\"abc\")",
                Keccak.keccak256Hex("abc".getBytes(StandardCharsets.UTF_8)).equals("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"));
        check("selector anchor", sel(Abi.SIG_ANCHOR).equals("2c4e3b68"));
        check("selector enroll", sel(Abi.SIG_ENROLL).equals("c6fd694e"));
        check("selector anchorCount", sel(Abi.SIG_ANCHOR_COUNT).equals("4cad6a99"));
        check("selector getLatest", sel(Abi.SIG_GET_LATEST).equals("d24678df"));
    }

    static String sel(String sig) {
        byte[] h = Keccak.selector(sig);
        StringBuilder sb = new StringBuilder();
        for (byte b : h) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    static void signerRoundtrip() throws Exception {
        System.out.println("[signer]");
        KeyPair kp = KeyStore.defaults().loadOrCreate(); // also proves load-or-generate works
        Signer s = new Signer(kp.getPrivate());
        String sig = s.sign("a", 1, 100, h64(1), h64(2), h64(3), h64(4), h64(5));
        check("sign/verify roundtrip", Signer.verify(kp.getPublic(), "a", 1, 100, h64(1), h64(2), h64(3), h64(4), h64(5), sig));
        check("tampered field fails", !Signer.verify(kp.getPublic(), "a", 1, 100, h64(1), h64(2), h64(3), h64(4), h64(6), sig));
        check("wrong seq fails", !Signer.verify(kp.getPublic(), "a", 2, 100, h64(1), h64(2), h64(3), h64(4), h64(5), sig));
        char[] c = sig.toCharArray();
        c[c.length - 2] = c[c.length - 2] == 'A' ? 'B' : 'A';
        check("corrupt sig fails", !Signer.verify(kp.getPublic(), "a", 1, 100, h64(1), h64(2), h64(3), h64(4), h64(5), new String(c)));
    }

    static String h64(int salt) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 64; i++) sb.append(Integer.toHexString((salt + i) % 16));
        return sb.toString();
    }

    static void rawBytesRule() throws Exception {
        System.out.println("[hComb raw-bytes rule]");
        String a = h64(1), b = h64(2), c = h64(3);
        String combined = Measurer.combine(a, b, c);
        byte[] all = new byte[96];
        System.arraycopy(Measurer.hexToBytes(a), 0, all, 0, 32);
        System.arraycopy(Measurer.hexToBytes(b), 0, all, 32, 32);
        System.arraycopy(Measurer.hexToBytes(c), 0, all, 64, 32);
        String raw = Measurer.sha256Hex(all);
        String hexConcat = Measurer.sha256Hex((a + b + c).getBytes(StandardCharsets.UTF_8));
        check("combine == sha256(raw96)", combined.equals(raw));
        check("hex-concat is a DIFFERENT (wrong) value", !combined.equals(hexConcat));
    }

    // ---- the attack table: one fresh Verifier per verdict ----

    static Path dir;
    static Path bin, cfg;
    static Verifier.Baseline baseline;
    static KeyPair kp;
    static Signer signer;
    static final String AGENT = "agent-01";
    static final Map<String, String> STATE = Map.of("mode", "AUTO", "limit", "100", "version", "3");

    static void attackTable() throws Exception {
        System.out.println("[attack table]");
        dir = Files.createTempDirectory("integrity-selftest");
        bin = dir.resolve("AgentState.java");
        cfg = dir.resolve("agent-config.json");
        Files.writeString(bin, "class AgentState { int limit = 100; }\n");
        Files.writeString(cfg, "{\n  \"threshold\": 100\n}\n");

        Measurer.Measurement golden = Measurer.measure(bin, cfg, STATE);
        baseline = new Verifier.Baseline(AGENT, golden.hBin(), golden.hCfg(), golden.hMem(), golden.hComb(), "");
        kp = KeyStore.defaults().loadOrCreate();
        signer = new Signer(kp.getPrivate());

        long now = System.currentTimeMillis() / 1000;

        // OK: everything consistent, signed, chained from baseline
        {
            var v = fresh();
            var m = signed(Measurer.measure(bin, cfg, STATE), 1, now, baseline.hComb());
            var re = Measurer.measure(bin, cfg, STATE);
            check("OK", v.check(re, m, now, false).reason() == Verifier.Reason.OK);
        }

        // POLICY_CFG_CHANGED: file really edited, checker honest about it
        {
            String orig = Files.readString(cfg);
            Files.writeString(cfg, orig.replace("100", "999"));
            var v = fresh();
            var m = signed(Measurer.measure(bin, cfg, STATE), 1, now, baseline.hComb());
            var re = Measurer.measure(bin, cfg, STATE);
            var verdict = v.check(re, m, now, false);
            check("POLICY_CFG_CHANGED", verdict.reason() == Verifier.Reason.POLICY_CFG_CHANGED);
            check("  names component config", "config".equals(component(verdict.reason())));
            Files.writeString(cfg, orig);
        }

        // POLICY_BIN_CHANGED: source file edited
        {
            String orig = Files.readString(bin);
            Files.writeString(bin, "class AgentState { int limit = 666; }\n");
            var v = fresh();
            var m = signed(Measurer.measure(bin, cfg, STATE), 1, now, baseline.hComb());
            var re = Measurer.measure(bin, cfg, STATE);
            var verdict = v.check(re, m, now, false);
            check("POLICY_BIN_CHANGED", verdict.reason() == Verifier.Reason.POLICY_BIN_CHANGED);
            Files.writeString(bin, orig);
        }

        // POLICY_MEM_CHANGED: runtime state edited (no file touched)
        {
            var v = fresh();
            var lyingState = new HashMap<>(STATE); lyingState.put("limit", "999");
            var m = signed(Measurer.measure(bin, cfg, lyingState), 1, now, baseline.hComb());
            var re = Measurer.measure(bin, cfg, STATE); // Boss sees true state
            var verdict = v.check(re, m, now, false);
            // reported(mem=999) != re(mem=100) -> caught as lying checker first
            check("lying memory -> MEASURE_MISMATCH_MEM", verdict.reason() == Verifier.Reason.MEASURE_MISMATCH_MEM);
            // honest checker with changed memory -> POLICY_MEM_CHANGED
            var v2 = fresh();
            var m2 = signed(Measurer.measure(bin, cfg, lyingState), 1, now, baseline.hComb());
            var verdict2 = v2.check(Measurer.measure(bin, cfg, lyingState), m2, now, false);
            check("changed memory -> POLICY_MEM_CHANGED", verdict2.reason() == Verifier.Reason.POLICY_MEM_CHANGED);
            check("  names component memory", "memory".equals(component(verdict2.reason())));
        }

        // MEASURE_MISMATCH_CFG: checker signs a config hash that differs from disk
        {
            var v = fresh();
            String fake = Measurer.sha256Hex("evil".getBytes(StandardCharsets.UTF_8));
            var m = signed(new Measurer.Measurement(baseline.hBin(), fake, baseline.hMem(),
                    Measurer.combine(baseline.hBin(), fake, baseline.hMem())), 1, now, baseline.hComb());
            var re = Measurer.measure(bin, cfg, STATE);
            check("MEASURE_MISMATCH_CFG (lying checker)", v.check(re, m, now, false).reason() == Verifier.Reason.MEASURE_MISMATCH_CFG);
        }

        // SIG_FAIL: valid measurement, corrupted seal
        {
            var v = fresh();
            var good = signed(Measurer.measure(bin, cfg, STATE), 1, now, baseline.hComb());
            byte[] raw = java.util.Base64.getDecoder().decode(good.sig());
            raw[raw.length - 1] ^= 0x01;
            String badSig = java.util.Base64.getEncoder().encodeToString(raw);
            var bad = new SignedMeasurement(good.agentId(), good.seq(), good.ts(), good.hBin(), good.hCfg(),
                    good.hMem(), good.hComb(), good.prevHash(), badSig, "");
            check("SIG_FAIL", v.check(Measurer.measure(bin, cfg, STATE), bad, now, false).reason() == Verifier.Reason.SIG_FAIL);
        }

        // COMB_MISMATCH: hComb does not match its own components
        {
            var v = fresh();
            var good = signed(Measurer.measure(bin, cfg, STATE), 1, now, baseline.hComb());
            var bad = new SignedMeasurement(good.agentId(), good.seq(), good.ts(), good.hBin(), good.hCfg(),
                    good.hMem(), h64(9), good.prevHash(), good.sig(), "");
            check("COMB_MISMATCH", v.check(Measurer.measure(bin, cfg, STATE), bad, now, false).reason() == Verifier.Reason.COMB_MISMATCH);
        }

        // PREV_HASH_BREAK: forked history
        {
            var v = fresh();
            var m = signed(Measurer.measure(bin, cfg, STATE), 1, now, h64(7));
            check("PREV_HASH_BREAK", v.check(Measurer.measure(bin, cfg, STATE), m, now, false).reason() == Verifier.Reason.PREV_HASH_BREAK);
        }

        // STALE_REPLAY: old timestamp
        {
            var v = fresh();
            long old = now - 100;
            var m = signed(Measurer.measure(bin, cfg, STATE), 1, old, baseline.hComb());
            check("STALE_REPLAY (old ts)", v.check(Measurer.measure(bin, cfg, STATE), m, old, false).reason() == Verifier.Reason.STALE_REPLAY);
        }

        // STALE_REPLAY: reused sequence number
        {
            var v = fresh();
            var first = signed(Measurer.measure(bin, cfg, STATE), 1, now, baseline.hComb());
            v.check(Measurer.measure(bin, cfg, STATE), first, now, false);
            var replay = signed(Measurer.measure(bin, cfg, STATE), 1, now, first.hComb());
            check("STALE_REPLAY (seq reuse)", v.check(Measurer.measure(bin, cfg, STATE), replay, now, false).reason() == Verifier.Reason.STALE_REPLAY);
        }
    }

    /** Regression: sustained tamper must stay POLICY_CFG every cycle (no PREV_HASH drift). */
    static void sustainedTamperStaysPolicy() throws Exception {
        System.out.println("[sustained tamper]");
        String orig = Files.readString(cfg);
        Files.writeString(cfg, orig.replace("100", "999"));
        try {
            var v = fresh();
            long now = System.currentTimeMillis() / 1000;
            var m1 = signed(Measurer.measure(bin, cfg, STATE), 1, now, baseline.hComb());
            var r1 = v.check(Measurer.measure(bin, cfg, STATE), m1, now, false);
            check("cycle1 POLICY_CFG_CHANGED", r1.reason() == Verifier.Reason.POLICY_CFG_CHANGED);

            var m2 = signed(Measurer.measure(bin, cfg, STATE), 2, now + 5, m1.hComb());
            var r2 = v.check(Measurer.measure(bin, cfg, STATE), m2, now + 5, false);
            check("cycle2 still POLICY_CFG_CHANGED (not PREV_HASH_BREAK)", r2.reason() == Verifier.Reason.POLICY_CFG_CHANGED);

            // recovery flips back to OK
            Files.writeString(cfg, orig);
            var m3 = signed(Measurer.measure(bin, cfg, STATE), 3, now + 10, m2.hComb());
            var r3 = v.check(Measurer.measure(bin, cfg, STATE), m3, now + 10, false);
            check("recovery -> OK", r3.reason() == Verifier.Reason.OK);
        } finally {
            Files.writeString(cfg, orig);
        }
    }

    // ---- key pinning: a swapped key pair must not self-verify into GREEN ----

    static void keyPinning() throws Exception {
        System.out.println("[key pinning]");
        long now = System.currentTimeMillis() / 1000;

        // baseline parsing: with and without a pinned key
        Path tmp = Files.createTempFile("integrity-baseline", ".json");
        Files.writeString(tmp, "{\"agentId\":\"" + AGENT + "\",\"hBin\":\"" + h64(1) + "\",\"hCfg\":\"" + h64(2)
                + "\",\"hMem\":\"" + h64(3) + "\",\"hComb\":\"" + h64(4) + "\",\"prevHash\":\"" + h64(5)
                + "\",\"publicKey\":\"QUJDREVGR0g=\"}");
        check("baseline parses pinned public key", Verifier.loadBaseline(tmp).publicKey().equals("QUJDREVGR0g="));
        Files.writeString(tmp, "{\"agentId\":\"" + AGENT + "\",\"hBin\":\"" + h64(1) + "\",\"hCfg\":\"" + h64(2)
                + "\",\"hMem\":\"" + h64(3) + "\",\"hComb\":\"" + h64(4) + "\",\"prevHash\":\"" + h64(5) + "\"}");
        check("legacy baseline stays unpinned (fresh-clone friendly)", Verifier.loadBaseline(tmp).publicKey().isEmpty());

        // key swap: verifier holds the ATTACKER key, baseline pins the ENROLLED key
        String pin = KeyStore.pubB64(kp.getPublic());
        var pinned = new Verifier.Baseline(AGENT, baseline.hBin(), baseline.hCfg(), baseline.hMem(), baseline.hComb(), pin);
        var attacker = Signer.generate();
        var vSwap = new Verifier(AGENT, attacker.getPublic(), pinned, 12);
        var m = signed(Measurer.measure(bin, cfg, STATE), 1, now, baseline.hComb());
        var verdict = vSwap.check(Measurer.measure(bin, cfg, STATE), m, now, false);
        check("key swap -> KEY_MISMATCH", verdict.reason() == Verifier.Reason.KEY_MISMATCH);
        check("  names component key", "key".equals(component(verdict.reason())));
        check("  reports enrolled vs disk key", verdict.expected().equals(pin));

        // pin present + key matches -> normal GREEN path
        var vOk = new Verifier(AGENT, kp.getPublic(), pinned, 12);
        check("pinned + matching key -> OK", vOk.check(Measurer.measure(bin, cfg, STATE), m, now, false).reason() == Verifier.Reason.OK);

        // unpinned baseline still verifies (demo default)
        check("unpinned baseline -> OK", fresh().check(Measurer.measure(bin, cfg, STATE), m, now, false).reason() == Verifier.Reason.OK);
    }

    // ---- boss witness: independent, hash-chained counter-attestation ----

    static void witnessChain() throws Exception {
        System.out.println("[witness]");
        Path witFile = Files.createTempDirectory("integrity-witness").resolve("witness.jsonl");
        var w = new integrity.witness.Witness(witFile);
        long now = System.currentTimeMillis() / 1000;
        check("record 3 observations", w.record(1, now, "GREEN", "OK", "-", h64(1), h64(2))
                && w.record(2, now, "RED", "POLICY_CFG_CHANGED", "config", h64(3), h64(1))
                && w.record(3, now, "GREEN", "OK", "-", h64(4), h64(3)));
        check("3-line chain verifies", integrity.witness.Witness.verify(witFile, w.publicKey()));

        String orig = Files.readString(witFile);
        Files.writeString(witFile, orig.replace(h64(3), h64(9)));
        check("edited line breaks the chain", !integrity.witness.Witness.verify(witFile, w.publicKey()));
        Files.writeString(witFile, orig);
        check("restored chain verifies again", integrity.witness.Witness.verify(witFile, w.publicKey()));
        check("wrong boss key rejected", !integrity.witness.Witness.verify(witFile, Signer.generate().getPublic()));
        check("well-formed 64-byte sig", integrity.witness.Witness.wellFormedSig(
                Verifier.get(Files.readAllLines(witFile).get(0), "sig")));
    }

    static Verifier fresh() {
        return new Verifier(AGENT, kp.getPublic(), baseline, 12);
    }

    // ---- dashboard: witness object in /api/status (panel + evidence bundle source) ----

    static void dashboardWitnessJson() {
        System.out.println("[dashboard]");
        var d = new integrity.ui.Dashboard();
        var st = new integrity.ui.Dashboard.Status("GREEN", 7, "-", "OK",
                h64(1), h64(2), h64(3), h64(4), "tx", "detail", 1, 2, 3, true);
        check("status carries witness=null when unset", d.statusJson(st).contains("\"witness\":null"));
        d.setWitness(new integrity.ui.Dashboard.WitnessInfo(true, true, 3, h64(5), 42, "OK"));
        String j = d.statusJson(st);
        check("witness object exposes chainOk/lines/lastSeq",
                j.contains("\"witness\":{\"enabled\":true,\"chainOk\":true,\"lines\":3")
                        && j.contains("\"lastSeq\":42") && j.contains("\"lastVerdict\":\"OK\""));
    }

    static SignedMeasurement signed(Measurer.Measurement m, long seq, long ts, String prev) throws Exception {
        String sig = signer.sign(AGENT, seq, ts, m.hBin(), m.hCfg(), m.hMem(), m.hComb(), prev);
        return new SignedMeasurement(AGENT, seq, ts, m.hBin(), m.hCfg(), m.hMem(), m.hComb(), prev, sig, "test");
    }

    static String component(Verifier.Reason r) {
        return Verifier.diffHint(r).getOrDefault("component", "-");
    }

    // ---- Merkle scale ----

    static void merkleScale() throws Exception {
        System.out.println("[merkle 10k]");
        Random rnd = new Random(42);
        List<String> leaves = new ArrayList<>();
        for (int i = 0; i < 10_000; i++) leaves.add(h64(rnd.nextInt(16)) + h64(rnd.nextInt(16)));
        long t0 = System.nanoTime();
        String root = MerkleTree.root(leaves);
        long ms = (System.nanoTime() - t0) / 1_000_000;
        check("root builds < 2000ms (took " + ms + "ms)", ms < 2000);
        int idx = 4242;
        List<String> proof = MerkleTree.proof(leaves, idx);
        check("proof verifies", MerkleTree.verify(leaves.get(idx), proof, idx, root));
        List<String> bad = new ArrayList<>(proof);
        bad.set(0, h64(3));
        check("tampered proof rejected", !MerkleTree.verify(leaves.get(idx), bad, idx, root));
        check("wrong leaf rejected", !MerkleTree.verify(h64(15), proof, idx, root));
    }

    // ---- ABI layout ----

    static void abiEncoding() {
        System.out.println("[abi]");
        byte[] en = Abi.encEnroll("agent-01", h64(1), h64(2), h64(3), h64(4));
        check("enroll selector", Abi.hex(java.util.Arrays.copyOfRange(en, 0, 4)).equals("c6fd694e"));
        // head word0 = offset 5*32 = 160 = 0xa0
        String off = Abi.hex(java.util.Arrays.copyOfRange(en, 4, 36));
        check("string offset word = 160", off.matches("0{62}a0"));
        // length word right after 5 head words
        long len = Long.parseLong(Abi.hex(java.util.Arrays.copyOfRange(en, 4 + 5 * 32, 4 + 6 * 32)), 16);
        check("agentId length word = 8", len == "agent-01".length());

        byte[] an = Abi.encAnchor("agent-01", 7, h64(1), h64(2), h64(3), h64(4), h64(5), new byte[64]);
        check("anchor selector", Abi.hex(java.util.Arrays.copyOfRange(an, 0, 4)).equals("2c4e3b68"));
        long seq = Long.parseLong(Abi.hex(java.util.Arrays.copyOfRange(an, 4 + 32, 4 + 64)), 16);
        check("seq word = 7", seq == 7);
        long strOff = Long.parseLong(Abi.hex(java.util.Arrays.copyOfRange(an, 4, 36)), 16);
        check("anchor string offset = 256", strOff == 256);
        long sigOff = Long.parseLong(Abi.hex(java.util.Arrays.copyOfRange(an, 4 + 7 * 32, 4 + 8 * 32)), 16);
        long expectedSigOff = 256 + 32 + ((8 + 31) / 32) * 32;
        check("sig offset word correct", sigOff == expectedSigOff);
    }

    // ---- chain receipt semantics ----

    static void chainReceipt() {
        System.out.println("[chain receipt]");
        check("only mined 0x1 confirms; null pending and 0x0 revert do not",
                !ChainAnchor.confirmed(null)
                        && !ChainAnchor.confirmed("0x0")
                        && ChainAnchor.confirmed("0x1"));
    }

    // ---- seq persistence ----

    static void seqPersistence() throws Exception {
        System.out.println("[seq store]");
        Path p = Files.createTempDirectory("integrity-seq").resolve("seq.dat");
        SeqStore s = new SeqStore(p);
        s.save(4321);
        check("save/load roundtrip", new SeqStore(p).load() == 4321);
        check("missing file defaults to 1 (genesis 0 -> first live 1)", new SeqStore(p.resolveSibling("nope.dat")).load() == 1);
    }
}
