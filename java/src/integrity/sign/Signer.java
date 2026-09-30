package integrity.sign;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/**
 * Frozen contract — wax seal over ALL component hashes plus chain linkage.
 * Signed payload (UTF-8, pipe-separated):
 *   agentId|seq|ts|hBin|hCfg|hMem|hComb|prevHash
 * Private stays with Checker, public stays with Boss (enrolled Phase 0).
 */
public final class Signer {
    private final PrivateKey priv;

    public Signer(PrivateKey priv) { this.priv = priv; }

    public static KeyPair generate() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519");
        return g.generateKeyPair();
    }

    public static String payload(String agentId, long seq, long ts,
                                 String hBin, String hCfg, String hMem,
                                 String hComb, String prevHash) {
        return agentId + "|" + seq + "|" + ts + "|"
                + hBin.toLowerCase() + "|" + hCfg.toLowerCase() + "|" + hMem.toLowerCase() + "|"
                + hComb.toLowerCase() + "|" + prevHash.toLowerCase();
    }

    public String sign(String agentId, long seq, long ts,
                       String hBin, String hCfg, String hMem,
                       String hComb, String prevHash) throws Exception {
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(priv);
        s.update(payload(agentId, seq, ts, hBin, hCfg, hMem, hComb, prevHash).getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(s.sign());
    }

    public static boolean verify(PublicKey pub, String agentId, long seq, long ts,
                                 String hBin, String hCfg, String hMem,
                                 String hComb, String prevHash, String sigB64) throws Exception {
        Signature s = Signature.getInstance("Ed25519");
        s.initVerify(pub);
        s.update(payload(agentId, seq, ts, hBin, hCfg, hMem, hComb, prevHash).getBytes(StandardCharsets.UTF_8));
        return s.verify(Base64.getDecoder().decode(sigB64));
    }
}
