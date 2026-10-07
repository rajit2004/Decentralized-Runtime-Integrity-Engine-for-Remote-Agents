package integrity.chain;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Minimal manual ABI encoder for the two Integrity.sol writes plus two reads.
 * Static types (uint64, bytes32) are single 32-byte words; string/bytes are
 * dynamic (head offset + length word + data padded to 32). No web3j.
 */
public final class Abi {
    private Abi() {}

    public static final String SIG_ENROLL = "enroll(string,bytes32,bytes32,bytes32,bytes32)";
    public static final String SIG_ANCHOR = "anchor(string,uint64,bytes32,bytes32,bytes32,bytes32,bytes32,bytes)";
    public static final String SIG_ANCHOR_COUNT = "anchorCount(bytes32)";
    public static final String SIG_GET_LATEST = "getLatest(string)";

    static byte[] word(long v) {
        byte[] w = new byte[32];
        for (int i = 0; i < 8; i++) w[31 - i] = (byte) (v >>> (8 * i));
        return w;
    }

    static byte[] wordFromHex(String hex) {
        String h = hex.startsWith("0x") || hex.startsWith("0X") ? hex.substring(2) : hex;
        byte[] out = new byte[32];
        for (int i = 0; i < 32 && i * 2 + 1 < h.length(); i++)
            out[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    static int padded(int len) { return len + (32 - (len % 32)) % 32; }

    static byte[] tail(byte[] data) {
        byte[] t = new byte[32 + padded(data.length)];
        System.arraycopy(word(data.length), 0, t, 0, 32);
        System.arraycopy(data, 0, t, 32, data.length);
        return t;
    }

    static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, out, o, p.length); o += p.length; }
        return out;
    }

    public static byte[] encGetLatest(String agentId) {
        byte[] id = agentId.getBytes(StandardCharsets.UTF_8);
        return concat(Keccak.selector(SIG_GET_LATEST), word(32), tail(id));
    }

    public static byte[] encAnchorCount(byte[] key32) {
        return concat(Keccak.selector(SIG_ANCHOR_COUNT), key32);
    }

    // ---- getLatest return codec: (Record) = wrapper offset + struct head + sig tail ----

    /** On-chain Record decoded from eth_call getLatest. sig = raw contract bytes. */
    public record ChainRecord(String hBin, String hCfg, String hMem, String hComb,
                              String prevHash, long seq, long ts, byte[] sig) {}

    private static long wordToLong(byte[] w, int off) {
        long v = 0;
        for (int i = off + 24; i < off + 32; i++) v = (v << 8) | (w[i] & 0xff);
        return v;
    }

    private static long wordToUint(byte[] w, int off) {
        // uint256 word holding a small offset/length: fail loud if it does not fit
        java.math.BigInteger bi = new java.math.BigInteger(1, java.util.Arrays.copyOfRange(w, off, off + 32));
        return bi.longValueExact();
    }

    /**
     * Decode eth_call("getLatest") return data. Layout: solidity wraps a struct
     * containing dynamic data behind a leading 0x20 offset; a flat struct (no
     * wrapper) is also accepted so a node/abi variant still parses.
     * Returns null for malformed input (never throws on chain garbage).
     */
    public static ChainRecord decodeLatest(String hex) {
        try {
            String h = (hex == null) ? "" : (hex.startsWith("0x") ? hex.substring(2) : hex);
            if (h.length() < 8 * 64 || h.length() % 2 != 0) return null;
            byte[] b = new byte[h.length() / 2];
            for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
            int base = (wordToLong(b, 0) == 0x20) ? 0x20 : 0;   // wrapper offset or flat struct
            if (b.length < base + 8 * 32) return null;
            long sigOff = wordToUint(b, base + 7 * 32);
            if (sigOff < 0 || base + sigOff + 32 > b.length) return null;
            long sigLen = wordToUint(b, base + (int) sigOff);
            if (sigLen < 0 || base + sigOff + 32 + sigLen > b.length) return null;
            byte[] sig = java.util.Arrays.copyOfRange(b, base + (int) sigOff + 32,
                    base + (int) sigOff + 32 + (int) sigLen);
            return new ChainRecord(
                    hex(b, base), hex(b, base + 32), hex(b, base + 64), hex(b, base + 96), hex(b, base + 128),
                    wordToLong(b, base + 5 * 32), wordToLong(b, base + 6 * 32), sig);
        } catch (Exception e) {
            return null;
        }
    }

    private static String hex(byte[] b, int off) {
        StringBuilder sb = new StringBuilder(64);
        for (int i = off; i < off + 32; i++) sb.append(String.format("%02x", b[i]));
        return sb.toString();
    }

    /** Reference encoder for a ChainRecord return payload (fixtures / round-trip tests). */
    public static String encodeLatest(ChainRecord r) {
        byte[] tailSig = tail(r.sig());
        long sigOff = 8L * 32; // relative to struct start (after wrapper word)
        byte[] struct = concat(
                wordFromHex(r.hBin()), wordFromHex(r.hCfg()), wordFromHex(r.hMem()),
                wordFromHex(r.hComb()), wordFromHex(r.prevHash()),
                word(r.seq()), word(r.ts()), word(sigOff), tailSig);
        return hex(concat(word(0x20), struct));
    }

    public static byte[] encEnroll(String agentId, String hBin, String hCfg, String hMem, String hComb) {
        byte[] id = agentId.getBytes(StandardCharsets.UTF_8);
        byte[] head = concat(word(5L * 32), wordFromHex(hBin), wordFromHex(hCfg), wordFromHex(hMem), wordFromHex(hComb));
        return concat(Keccak.selector(SIG_ENROLL), head, tail(id));
    }

    public static byte[] encAnchor(String agentId, long seq, String hBin, String hCfg, String hMem,
                            String hComb, String prevHash, byte[] sig) {
        byte[] id = agentId.getBytes(StandardCharsets.UTF_8);
        long strOff = 8L * 32;
        long sigOff = strOff + 32 + padded(id.length);
        byte[] head = concat(word(strOff), word(seq),
                wordFromHex(hBin), wordFromHex(hCfg), wordFromHex(hMem),
                wordFromHex(hComb), wordFromHex(prevHash), word(sigOff));
        return concat(Keccak.selector(SIG_ANCHOR), head, tail(id), tail(sig));
    }

    public static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
