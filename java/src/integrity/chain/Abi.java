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
