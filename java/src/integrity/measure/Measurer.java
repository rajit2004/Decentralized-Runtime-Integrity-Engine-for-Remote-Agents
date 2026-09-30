package integrity.measure;

import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/**
 * Takes SHA-256 fingerprints of binary + config + whitelisted memory.
 * Canonical memory: TreeMap sorted keys -> "k=v;k=v" (no JSON lib needed).
 *
 * Frozen contract: hashes are 64-char lowercase hex.
 * hComb = SHA256(raw32(hBin) || raw32(hCfg) || raw32(hMem)), NOT hex strings.
 */
public final class Measurer {
    private Measurer() {}

    public static final String ZERO_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    public static String sha256Hex(byte[] data) throws Exception {
        MessageDigest d = MessageDigest.getInstance("SHA-256");
        byte[] h = d.digest(data);
        StringBuilder sb = new StringBuilder(h.length * 2);
        for (byte b : h) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /**
     * Windows-safe read: retry once after 200ms on sharing violation (item 20).
     * Missing file throws -> caller treats as tamper, never as OK.
     */
    public static String hashFile(Path p) throws Exception {
        try {
            return sha256Hex(Files.readAllBytes(p));
        } catch (java.io.IOException e) {
            Thread.sleep(200);
            return sha256Hex(Files.readAllBytes(p)); // throws again -> tamper path
        }
    }

    public static String canonicalState(Map<String, String> state) {
        TreeMap<String, String> sorted = new TreeMap<>(state);
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : sorted.entrySet()) {
            sb.append(e.getKey()).append('=').append(e.getValue()).append(';');
        }
        return sb.toString();
    }

    public static String hashState(Map<String, String> state) throws Exception {
        return sha256Hex(canonicalState(state).getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    public static byte[] hexToBytes(String hex) {
        int n = hex.length();
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }

    /** Frozen: combine raw 32-byte values, 96 bytes total. */
    public static String combine(String hBin, String hCfg, String hMem) throws Exception {
        byte[] b1 = hexToBytes(hBin.toLowerCase());
        byte[] b2 = hexToBytes(hCfg.toLowerCase());
        byte[] b3 = hexToBytes(hMem.toLowerCase());
        byte[] all = new byte[96];
        System.arraycopy(b1, 0, all, 0, 32);
        System.arraycopy(b2, 0, all, 32, 32);
        System.arraycopy(b3, 0, all, 64, 32);
        return sha256Hex(all);
    }

    public record Measurement(String hBin, String hCfg, String hMem, String hComb) {}

    public static Measurement measure(Path binPath, Path cfgPath, Map<String, String> state) throws Exception {
        String h1 = hashFile(binPath).toLowerCase();
        String h2 = hashFile(cfgPath).toLowerCase();
        String h3 = hashState(state).toLowerCase();
        return new Measurement(h1, h2, h3, combine(h1, h2, h3));
    }
}
