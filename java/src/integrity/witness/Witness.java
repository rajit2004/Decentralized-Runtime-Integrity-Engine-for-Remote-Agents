package integrity.witness;

import integrity.measure.Measurer;
import integrity.sign.KeyStore;
import integrity.sign.Signer;
import integrity.verify.Verifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;

/**
 * Boss counter-attestation. After every cycle the Boss signs its OWN observation
 * (seq, ts, state, verdict, component) with a separate witness key and appends it
 * to witness.jsonl, hash-chained line by line.
 *
 * Why it matters for the stolen-key question: an attacker who steals the AGENT
 * key can forge agent signatures, but cannot forge lines under the witness key
 * and cannot rewrite earlier lines without breaking the SHA-256 chain. Comparing
 * the agent-signed chain against the boss-signed witness chain later is how you
 * prove the agent was lying and roughly when it started.
 *
 * Stated limit (software-only): in this single-box demo both keys sit on the
 * same machine. Real deployment keeps the witness key on the Boss host only.
 * TPM/TEE is the fix for key theft itself.
 */
public final class Witness {
    private static final String GENESIS = "0".repeat(64);
    private final Signer signer;
    private final PublicKey pub;
    private final Path file;
    private String prevLineHash = GENESIS;
    private int lines = 0;

    public Witness() {
        this(Paths.get("witness.jsonl"));
    }

    public Witness(Path file) {
        this.file = file;
        try {
            var kp = KeyStore.named("witness").loadOrCreate();
            this.signer = new Signer(kp.getPrivate());
            this.pub = kp.getPublic();
            resumeTail();
        } catch (Exception e) {
            throw new RuntimeException("witness key load failed: " + e, e);
        }
    }

    public PublicKey publicKey() { return pub; }
    public Path file() { return file; }
    public int lineCount() { return lines; }
    public String head() { return prevLineHash; }

    private void resumeTail() {
        try {
            if (!Files.exists(file)) return;
            List<String> lines = Files.readAllLines(file);
            for (String l : lines) if (!l.isBlank()) {
                prevLineHash = Measurer.sha256Hex(l.getBytes(StandardCharsets.UTF_8));
                this.lines++;
            }
        } catch (Exception ignored) { /* fresh chain start */ }
    }

    public static String payload(long seq, long ts, String state, String verdict, String comp,
                                 String hComb, String prevHash, String prevLine) {
        return "witness|" + seq + "|" + ts + "|" + state + "|" + verdict + "|" + comp
                + "|" + hComb.toLowerCase() + "|" + prevHash.toLowerCase() + "|" + prevLine;
    }

    /** Append one signed observation. Returns false on IO failure (never breaks the heartbeat). */
    public synchronized boolean record(long seq, long ts, String state, String verdict, String comp,
                                       String hComb, String prevHash) {
        try {
            String sig = signer.signPayload(payload(seq, ts, state, verdict, comp, hComb, prevHash, prevLineHash));
            String line = "{\"seq\":" + seq + ",\"ts\":" + ts
                    + ",\"state\":\"" + state + "\",\"verdict\":\"" + verdict + "\",\"comp\":\"" + comp
                    + "\",\"hComb\":\"" + hComb.toLowerCase() + "\",\"prevHash\":\"" + prevHash.toLowerCase()
                    + "\",\"prevLine\":\"" + prevLineHash + "\",\"sig\":\"" + sig + "\"}";
            Files.writeString(file, line + "\n", StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            prevLineHash = Measurer.sha256Hex(line.getBytes(StandardCharsets.UTF_8));
            lines++;
            return true;
        } catch (Exception e) {
            System.out.println("WITNESS_ERR " + e);
            return false;
        }
    }

    /** Verify the whole chain: line linkage + witness signatures. Used by SelfTest and audits. */
    public static boolean verify(Path file, PublicKey witnessPub) {
        try {
            if (!Files.exists(file)) return false;
            List<String> lines = Files.readAllLines(file);
            String prev = GENESIS;
            for (String line : lines) {
                if (line.isBlank()) continue;
                if (!Verifier.get(line, "prevLine").equals(prev)) return false;
                String sig = Verifier.get(line, "sig");
                String p = payload(Long.parseLong(Verifier.get(line, "seq")),
                        Long.parseLong(Verifier.get(line, "ts")),
                        Verifier.get(line, "state"), Verifier.get(line, "verdict"),
                        Verifier.get(line, "comp"), Verifier.get(line, "hComb"),
                        Verifier.get(line, "prevHash"), prev);
                if (!Signer.verifyPayload(witnessPub, p, sig)) return false;
                prev = Measurer.sha256Hex(line.getBytes(StandardCharsets.UTF_8));
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /** True when the sig is valid base64 of expected length (sanity for audits). */
    public static boolean wellFormedSig(String sigB64) {
        try { return Base64.getDecoder().decode(sigB64).length == 64; }
        catch (Exception e) { return false; }
    }
}
