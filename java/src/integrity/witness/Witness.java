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
    static final int ROTATE_AT = 50_000;
    private final Signer signer;
    private final PublicKey pub;
    private final Path file;
    private final int rotateAt;
    private String prevLineHash = GENESIS;
    private int lines = 0;

    public Witness() {
        this(Paths.get("witness.jsonl"));
    }

    public Witness(Path file) {
        this(file, ROTATE_AT);
    }

    /** rotateAt: archive + carry-line rotation threshold (tests use small values). */
    public Witness(Path file, int rotateAt) {
        this.file = file;
        this.rotateAt = rotateAt;
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
            if (lines >= rotateAt) rotate();
            return true;
        } catch (Exception e) {
            System.out.println("WITNESS_ERR " + e);
            return false;
        }
    }

    /** Rotation: archive the full chain, start a fresh file with a signed carry line
     *  that authenticates the archived head (chain stays verifiable across files). */
    private void rotate() {
        try {
            Path archive = file.resolveSibling(file.getFileName() + "." + System.currentTimeMillis());
            Files.move(file, archive, StandardCopyOption.REPLACE_EXISTING);
            String head = prevLineHash;
            long ts = System.currentTimeMillis() / 1000;
            String from = archive.getFileName().toString();
            String sig = signer.signPayload(carryPayload(from, head, ts));
            String line = "{\"carry\":1,\"ts\":" + ts + ",\"from\":\"" + from
                    + "\",\"head\":\"" + head + "\",\"prevLine\":\"" + head + "\",\"sig\":\"" + sig + "\"}";
            Files.writeString(file, line + "\n", StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            prevLineHash = Measurer.sha256Hex(line.getBytes(StandardCharsets.UTF_8));
            lines = 1;
            System.out.println("WITNESS rotated -> " + from + " carry head=" + head.substring(0, 12) + "...");
        } catch (Exception e) {
            System.out.println("WITNESS_ROTATE_ERR " + e);
        }
    }

    static String carryPayload(String from, String head, long ts) {
        return "witness-carry|" + from + "|" + head + "|" + ts;
    }

    /** Verify the whole chain: line linkage + witness signatures. Used by SelfTest and audits.
     *  A rotated file starts with a signed carry line that authenticates the archived head. */
    public static boolean verify(Path file, PublicKey witnessPub) {
        try {
            if (!Files.exists(file)) return false;
            List<String> lines = Files.readAllLines(file);
            String prev = GENESIS;
            boolean first = true;
            for (String line : lines) {
                if (line.isBlank()) continue;
                if (line.contains("\"carry\":1")) {
                    // carry line must open the file; its signature authenticates the prior head
                    if (!first) return false;
                    String head = Verifier.get(line, "head");
                    String ts = Verifier.get(line, "ts");
                    String from = Verifier.get(line, "from");
                    if (head.length() != 64 || !Verifier.get(line, "prevLine").equals(head)) return false;
                    if (!Signer.verifyPayload(witnessPub, carryPayload(from, head, Long.parseLong(ts)),
                            Verifier.get(line, "sig"))) return false;
                    prev = Measurer.sha256Hex(line.getBytes(StandardCharsets.UTF_8));
                    first = false;
                    continue;
                }
                if (!Verifier.get(line, "prevLine").equals(prev)) return false;
                String sig = Verifier.get(line, "sig");
                String p = payload(Long.parseLong(Verifier.get(line, "seq")),
                        Long.parseLong(Verifier.get(line, "ts")),
                        Verifier.get(line, "state"), Verifier.get(line, "verdict"),
                        Verifier.get(line, "comp"), Verifier.get(line, "hComb"),
                        Verifier.get(line, "prevHash"), prev);
                if (!Signer.verifyPayload(witnessPub, p, sig)) return false;
                prev = Measurer.sha256Hex(line.getBytes(StandardCharsets.UTF_8));
                first = false;
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
