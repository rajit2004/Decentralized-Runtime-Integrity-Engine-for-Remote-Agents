package integrity.sign;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/**
 * Wax seal: Ed25519 sign(agentId|hComb|timestamp|nonce).
 * Private stays with Checker, public stays with Boss (enrolled in Phase 0).
 */
public final class Signer {
    private final PrivateKey priv;

    public Signer(PrivateKey priv) { this.priv = priv; }

    public static KeyPair generate() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519");
        return g.generateKeyPair();
    }

    public static String payload(String agentId, String hComb, long ts, long nonce) {
        return agentId + "|" + hComb + "|" + ts + "|" + nonce;
    }

    public String sign(String agentId, String hComb, long ts, long nonce) throws Exception {
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(priv);
        s.update(payload(agentId, hComb, ts, nonce).getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(s.sign());
    }

    public static boolean verify(PublicKey pub, String agentId, String hComb, long ts, long nonce, String sigB64) throws Exception {
        Signature s = Signature.getInstance("Ed25519");
        s.initVerify(pub);
        s.update(payload(agentId, hComb, ts, nonce).getBytes(StandardCharsets.UTF_8));
        return s.verify(Base64.getDecoder().decode(sigB64));
    }
}
