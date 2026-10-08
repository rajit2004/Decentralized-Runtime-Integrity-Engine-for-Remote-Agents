package integrity.chain;

/**
 * Minimal RLP encoding for legacy (type-0) Ethereum transactions.
 * Items are byte[] (strings/ints); lists are byte[][] payload items.
 */
public final class Rlp {
    private Rlp() {}

    /** RLP string/bytes rules: single byte < 0x80 is itself; short/long forms otherwise. */
    public static byte[] bytes(byte[] b) {
        if (b.length == 1 && (b[0] & 0xff) < 0x80) return b;
        if (b.length <= 55) return join(new byte[]{(byte) (0x80 + b.length)}, b);
        byte[] len = longBytes(b.length);
        return join(new byte[]{(byte) (0xb7 + len.length)}, len, b);
    }

    /** RLP list over pre-encoded items. */
    public static byte[] list(byte[]... items) {
        byte[] payload = join(items);
        if (payload.length <= 55) return join(new byte[]{(byte) (0xc0 + payload.length)}, payload);
        byte[] len = longBytes(payload.length);
        return join(new byte[]{(byte) (0xf7 + len.length)}, len, payload);
    }

    /** Minimal big-endian integer bytes; 0 -> empty (RLP 0x80). */
    public static byte[] longBytes(long v) {
        if (v < 0) throw new IllegalArgumentException("rlp: negative int");
        if (v == 0) return new byte[0];
        int n = 8;
        while (n > 1 && ((v >>> ((n - 1) * 8)) == 0)) n--;
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) out[n - 1 - i] = (byte) (v >>> (i * 8));
        return out;
    }

    /** Unsigned legacy list incl. EIP-155 [chainId, 0, 0] tail (hash this, then sign). */
    public static byte[] unsignedLegacy(long nonce, long gasPrice, long gasLimit, byte[] to,
                                        long value, byte[] data, long chainId) {
        return list(bytes(longBytes(nonce)), bytes(longBytes(gasPrice)), bytes(longBytes(gasLimit)),
                bytes(to), bytes(longBytes(value)), bytes(data == null ? new byte[0] : data),
                bytes(longBytes(chainId)), bytes(new byte[0]), bytes(new byte[0]));
    }

    /** Signed legacy list [nonce..data, v, r, s] ready for eth_sendRawTransaction. */
    public static byte[] signedLegacy(long nonce, long gasPrice, long gasLimit, byte[] to,
                                      long value, byte[] data, long v, byte[] r, byte[] s) {
        return list(bytes(longBytes(nonce)), bytes(longBytes(gasPrice)), bytes(longBytes(gasLimit)),
                bytes(to), bytes(longBytes(value)), bytes(data == null ? new byte[0] : data),
                bytes(longBytes(v)), bytes(r), bytes(s));
    }

    private static byte[] join(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, out, o, p.length); o += p.length; }
        return out;
    }
}
