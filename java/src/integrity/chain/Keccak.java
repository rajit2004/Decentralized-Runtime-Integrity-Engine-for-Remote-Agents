package integrity.chain;

import java.util.Arrays;

/**
 * Pure-JDK Keccak-256 (Ethereum flavor: pad 0x01..0x80, NOT NIST SHA-3's 0x06).
 * Needed because the JDK's SHA3-256 is the NIST variant, so Solidity function
 * selectors and agentKey() = keccak256(bytes(agentId)) must be computed here.
 * Zero dependencies keeps the JDK-only promise.
 */
public final class Keccak {
    private Keccak() {}

    private static final long[] RC = {
        0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL, 0x8000000080008000L,
        0x000000000000808bL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
        0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L, 0x8000000000008003L,
        0x8000000000008002L, 0x8000000000000080L, 0x000000000000800aL, 0x800000008000000aL,
        0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };
    private static final int[] ROTC = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
    private static final int[] PILN = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};

    public static byte[] keccak256(byte[] input) {
        int rate = 136; // 1088-bit rate for 256-bit output
        byte[] padded = Arrays.copyOf(input, ((input.length / rate) + 1) * rate);
        padded[input.length] |= 0x01;
        padded[padded.length - 1] |= (byte) 0x80;

        long[] s = new long[25];
        for (int off = 0; off < padded.length; off += rate) {
            for (int i = 0; i < rate / 8; i++) {
                long lane = 0;
                for (int b = 0; b < 8; b++) lane |= (padded[off + i * 8 + b] & 0xffL) << (8 * b);
                s[i] ^= lane;
            }
            keccakF(s);
        }

        byte[] out = new byte[32];
        for (int i = 0; i < 4; i++) {
            for (int b = 0; b < 8; b++) out[i * 8 + b] = (byte) (s[i] >>> (8 * b));
        }
        return out;
    }

    public static String keccak256Hex(byte[] input) {
        byte[] h = keccak256(input);
        StringBuilder sb = new StringBuilder(64);
        for (byte b : h) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** 4-byte Solidity function selector for a canonical signature. */
    public static byte[] selector(String signature) {
        byte[] h = keccak256(signature.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return Arrays.copyOf(h, 4);
    }

    private static void keccakF(long[] s) {
        for (int round = 0; round < 24; round++) {
            long[] c = new long[5];
            for (int i = 0; i < 5; i++) c[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
            for (int i = 0; i < 5; i++) {
                long d = c[(i + 4) % 5] ^ Long.rotateLeft(c[(i + 1) % 5], 1);
                for (int j = 0; j < 25; j += 5) s[j + i] ^= d;
            }
            long last = s[1];
            for (int i = 0; i < 24; i++) {
                int j = PILN[i];
                long t = s[j];
                s[j] = Long.rotateLeft(last, ROTC[i]);
                last = t;
            }
            for (int j = 0; j < 25; j += 5) {
                long[] row = new long[5];
                for (int i = 0; i < 5; i++) row[i] = s[j + i];
                for (int i = 0; i < 5; i++) s[j + i] = row[i] ^ ((~row[(i + 1) % 5]) & row[(i + 2) % 5]);
            }
            s[0] ^= RC[round];
        }
    }
}
