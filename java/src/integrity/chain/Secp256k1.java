package integrity.chain;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Pure-JDK secp256k1 ECDSA + EIP-155 signatures for local dev-chain transactions.
 * No third-party libraries and no JCA provider curve restrictions: point math and
 * signing are plain BigInteger arithmetic over the secp256k1 field.
 *
 * Scope (honest): k comes from SecureRandom (not RFC 6979) and signing is not
 * constant-time - fine for localhost hardhat/Anvil keys that hold no real funds.
 * A production deployment should sign in an HSM/wallet, never from a chain.json key.
 */
public final class Secp256k1 {
    static final BigInteger P = new BigInteger(
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16);
    static final BigInteger N = new BigInteger(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16);
    static final BigInteger GX = new BigInteger(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16);
    static final BigInteger GY = new BigInteger(
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16);
    private static final BigInteger HALF_N = N.shiftRight(1);
    private static final SecureRandom RND = new SecureRandom();

    /** EIP-155 signed values: v = 35 + chainId*2 + recId, r/s fixed 32-byte. */
    public record Sig(long v, byte[] r, byte[] s) {}

    /** Affine point; null = point at infinity. */
    record Pt(BigInteger x, BigInteger y) {}

    private Secp256k1() {}

    // ---- curve arithmetic (a = 0, b = 7) ----

    static Pt add(Pt a, Pt b) {
        if (a == null) return b;
        if (b == null) return a;
        BigInteger x1 = a.x(), y1 = a.y(), x2 = b.x(), y2 = b.y();
        BigInteger lam;
        if (x1.equals(x2)) {
            if (y1.add(y2).mod(P).signum() == 0) return null;
            // doubling: lambda = 3x^2 / 2y
            lam = x1.modPow(BigInteger.TWO, P).multiply(BigInteger.valueOf(3)).mod(P)
                    .multiply(y1.shiftLeft(1).mod(P).modInverse(P)).mod(P);
        } else {
            lam = y2.subtract(y1).mod(P).multiply(x2.subtract(x1).mod(P).modInverse(P)).mod(P);
        }
        BigInteger x3 = lam.multiply(lam).subtract(x1).subtract(x2).mod(P);
        BigInteger y3 = lam.multiply(x1.subtract(x3)).subtract(y1).mod(P);
        return new Pt(x3, y3);
    }

    static Pt mul(Pt p, BigInteger k) {
        if (p == null || k.signum() == 0) return null;
        Pt r = null;
        for (int i = k.bitLength() - 1; i >= 0; i--) {
            r = add(r, r);
            if (k.testBit(i)) r = add(r, p);
        }
        return r;
    }

    static Pt g() { return new Pt(GX, GY); }

    // ---- keys / addresses ----

    static BigInteger priv(byte[] priv32) {
        BigInteger d = new BigInteger(1, priv32);
        if (priv32.length != 32 || d.signum() == 0 || d.compareTo(N) >= 0)
            throw new IllegalArgumentException("bad secp256k1 private key");
        return d;
    }

    /** Uncompressed public key, 64 bytes x||y. */
    public static byte[] publicKey(byte[] priv32) {
        Pt q = mul(g(), priv(priv32));
        if (q == null) throw new IllegalStateException("pubkey at infinity");
        return concat(to32(q.x()), to32(q.y()));
    }

    /** Ethereum address: keccak256(pub64)[12..31], 0x + lowercase hex. */
    public static String addressOf(byte[] pub64) {
        byte[] h = Keccak.keccak256(pub64);
        return "0x" + Abi.hex(java.util.Arrays.copyOfRange(h, 12, 32));
    }

    public static String addressHex(byte[] priv32) { return addressOf(publicKey(priv32)); }

    // ---- ECDSA ----

    /** Sign a 32-byte digest with EIP-155 v for the given chainId (low-S, self-verified). */
    public static Sig sign(byte[] priv32, byte[] hash32, long chainId) {
        if (hash32.length != 32) throw new IllegalArgumentException("digest must be 32 bytes");
        BigInteger d = priv(priv32);
        BigInteger z = new BigInteger(1, hash32);
        Pt q = mul(g(), d);
        while (true) {
            byte[] kb = new byte[32];
            RND.nextBytes(kb);
            BigInteger k = new BigInteger(1, kb).mod(N);
            if (k.signum() == 0) continue;
            Pt rPt = mul(g(), k);
            BigInteger r = new BigInteger(1, to32(rPt.x())).mod(N);
            if (r.signum() == 0) continue;
            BigInteger s = k.modInverse(N).multiply(z.add(r.multiply(d)).mod(N)).mod(N);
            if (s.signum() == 0) continue;
            int recId = (rPt.y().testBit(0) ? 1 : 0) + (rPt.x().compareTo(N) >= 0 ? 2 : 0);
            if (s.compareTo(HALF_N) > 0) { s = N.subtract(s); recId ^= 1; }
            if (!verify(q, hash32, r, s)) throw new IllegalStateException("ecdsa self-verify failed");
            long v = 35 + chainId * 2 + recId;
            return new Sig(v, to32(r), to32(s));
        }
    }

    static boolean verify(Pt q, byte[] hash32, BigInteger r, BigInteger s) {
        if (r.signum() == 0 || r.compareTo(N) >= 0 || s.signum() == 0 || s.compareTo(N) >= 0) return false;
        BigInteger z = new BigInteger(1, hash32);
        BigInteger sInv = s.modInverse(N);
        Pt p = add(mul(g(), z.multiply(sInv).mod(N)), mul(q, r.multiply(sInv).mod(N)));
        return p != null && new BigInteger(1, to32(p.x())).mod(N).equals(r);
    }

    /** ecrecover: digest + (r, s, recId) -> sender address (0x hex), null when invalid. */
    public static String recoverAddress(byte[] hash32, byte[] rB, byte[] sB, int recId) {
        BigInteger r = new BigInteger(1, rB), s = new BigInteger(1, sB);
        if (r.signum() == 0 || r.compareTo(N) >= 0 || s.signum() == 0 || s.compareTo(N) >= 0) return null;
        BigInteger x = r;
        if ((recId & 2) != 0) x = x.add(N);
        if (x.compareTo(P) >= 0) return null;
        // y^2 = x^3 + 7; p = 3 (mod 4) so sqrt = (y^2)^((p+1)/4)
        BigInteger y2 = x.modPow(BigInteger.valueOf(3), P).add(BigInteger.valueOf(7)).mod(P);
        BigInteger y = y2.modPow(P.add(BigInteger.ONE).shiftRight(2), P);
        if (!y.multiply(y).mod(P).equals(y2)) return null;
        if (y.testBit(0) != ((recId & 1) != 0)) y = P.subtract(y);
        BigInteger z = new BigInteger(1, hash32);
        // Q = r^-1 * (s*R - z*G)  (the inversion of s*k = z + r*d)
        Pt q = mul(add(mul(new Pt(x, y), s), mul(g(), z.negate().mod(N))), r.modInverse(N));
        if (q == null) return null;
        return addressOf(concat(to32(q.x()), to32(q.y())));
    }

    public static boolean isLowS(byte[] s) { return new BigInteger(1, s).compareTo(HALF_N) <= 0; }

    // ---- hex helpers ----

    /** 0x-tolerant hex -> bytes. */
    public static byte[] unhex(String h) {
        String s = h.startsWith("0x") || h.startsWith("0X") ? h.substring(2) : h;
        if ((s.length() & 1) != 0) s = "0" + s;
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return out;
    }

    static byte[] to32(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b.length == 32) return b;
        byte[] out = new byte[32];
        if (b.length > 32) System.arraycopy(b, b.length - 32, out, 0, 32);
        else System.arraycopy(b, 0, out, 32 - b.length, b.length);
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }
}
