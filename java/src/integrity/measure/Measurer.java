package integrity.measure;

import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/**
 * Takes SHA-256 fingerprints of binary + config + whitelisted memory.
 * Canonical memory: TreeMap sorted keys -> "k=v;k=v" (no JSON lib needed).
 */
public final class Measurer {
    private Measurer() {}

    public static String sha256Hex(byte[] data) throws Exception {
        MessageDigest d = MessageDigest.getInstance("SHA-256");
        byte[] h = d.digest(data);
        StringBuilder sb = new StringBuilder(h.length * 2);
        for (byte b : h) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static String hashFile(Path p) throws Exception {
        return sha256Hex(Files.readAllBytes(p));
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

    public record Measurement(String hBin, String hCfg, String hMem, String hComb) {}

    public static Measurement measure(Path binPath, Path cfgPath, Map<String, String> state) throws Exception {
        String h1 = hashFile(binPath);
        String h2 = hashFile(cfgPath);
        String h3 = hashState(state);
        String hComb = sha256Hex((h1 + h2 + h3).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return new Measurement(h1, h2, h3, hComb);
    }
}
