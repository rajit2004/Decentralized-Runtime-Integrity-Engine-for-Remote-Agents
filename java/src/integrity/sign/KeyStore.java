package integrity.sign;

import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

/**
 * Item 3: key lives OUTSIDE the writable agent folder (keys/, not config/).
 * Threat model (stated openly): attacker who can write config.json can READ
 * anything on the same box. File separation + locked perms raise the bar
 * but do NOT stop a root-level reader. Real fix = TPM/TEE (stretch goal).
 *
 * Layout:
 *   keys/agent-private.pkcs8   (Checker only, created once, never in git)
 *   keys/agent-public.x509      (Boss copy)
 * Demo: generated once if missing, perms tightened where the OS allows.
 */
public final class KeyStore {
    private final Path privPath;
    private final Path pubPath;

    public KeyStore(Path privPath, Path pubPath) {
        this.privPath = privPath; this.pubPath = pubPath;
    }

    public static KeyStore defaults() {
        return new KeyStore(Paths.get("keys/agent-private.pkcs8"), Paths.get("keys/agent-public.x509"));
    }

    /** Load or create. Returns KeyPair. Writes files with best-effort locked perms. */
    public KeyPair loadOrCreate() throws Exception {
        if (Files.exists(privPath) && Files.exists(pubPath)) {
            byte[] privB = Files.readAllBytes(privPath);
            byte[] pubB = Files.readAllBytes(pubPath);
            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            PrivateKey priv = kf.generatePrivate(new PKCS8EncodedKeySpec(privB));
            PublicKey pub = kf.generatePublic(new X509EncodedKeySpec(pubB));
            return new KeyPair(pub, priv);
        }
        KeyPair kp = Signer.generate();
        Files.createDirectories(privPath.getParent());
        Files.write(privPath, kp.getPrivate().getEncoded(),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Files.write(pubPath, kp.getPublic().getEncoded(),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        lockdown(privPath);
        System.out.println("KEYS generated: priv=" + privPath + " (checker only), pub=" + pubPath + " (boss)");
        System.out.println("ASSUMPTION: keys/ is outside the attacker-writable config/ dir. A reader with agent-box access can still read it — TPM/TEE is the real fix.");
        return kp;
    }

    /** Best-effort owner-only perms (POSIX; no-op on Windows ACLs — documented). */
    private static void lockdown(Path p) {
        try {
            java.util.Set<java.nio.file.attribute.PosixFilePermission> perms =
                    java.util.EnumSet.of(java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                            java.nio.file.attribute.PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(p, perms);
        } catch (Exception e) {
            System.out.println("KEYS note: POSIX lockdown not available (" + System.getProperty("os.name") + "); keep keys/ outside shared/writable dirs.");
        }
    }

    public static String pubB64(PublicKey pub) {
        return Base64.getEncoder().encodeToString(pub.getEncoded());
    }
}
