package integrity.batch;

import integrity.measure.Measurer;
import java.util.*;

/**
 * Scale fix: 10k devices x 5s heartbeat = ~2000 TPS, impossible on public chain.
 * Batch: collect one window of leaf hCombs, build Merkle tree, anchor ONLY root
 * once per minute. Each device keeps its Merkle proof. 10k leaves -> 1 tx/min
 * = 0.0167 TPS (120,000x reduction). Proving one measurement = proof path.
 *
 * Leaf = raw32(hComb). Parent = SHA256(leftRaw || rightRaw). Odd leaf duplicated.
 * All hex lowercase.
 */
public final class MerkleTree {
    private MerkleTree() {}

    public static String parent(String leftHex, String rightHex) throws Exception {
        byte[] l = Measurer.hexToBytes(leftHex.toLowerCase());
        byte[] r = Measurer.hexToBytes(rightHex.toLowerCase());
        byte[] all = new byte[64];
        System.arraycopy(l, 0, all, 0, 32);
        System.arraycopy(r, 0, all, 32, 32);
        return Measurer.sha256Hex(all);
    }

    public static String root(List<String> leaves) throws Exception {
        if (leaves.isEmpty()) return Measurer.ZERO_HASH;
        List<String> cur = new ArrayList<>(leaves);
        for (int i = 0; i < cur.size(); i++) cur.set(i, cur.get(i).toLowerCase());
        while (cur.size() > 1) {
            List<String> next = new ArrayList<>((cur.size() + 1) / 2);
            for (int i = 0; i < cur.size(); i += 2) {
                String l = cur.get(i);
                String r = (i + 1 < cur.size()) ? cur.get(i + 1) : l;
                next.add(parent(l, r));
            }
            cur = next;
        }
        return cur.get(0);
    }

    /** Proof path for leaf index: siblings bottom-up. */
    public static List<String> proof(List<String> leaves, int index) throws Exception {
        List<String> p = new ArrayList<>();
        List<String> cur = new ArrayList<>(leaves);
        for (int i = 0; i < cur.size(); i++) cur.set(i, cur.get(i).toLowerCase());
        int idx = index;
        while (cur.size() > 1) {
            int sib = (idx % 2 == 0) ? idx + 1 : idx - 1;
            if (sib >= cur.size()) sib = idx; // duplicated odd
            p.add(cur.get(sib));
            List<String> next = new ArrayList<>((cur.size() + 1) / 2);
            for (int i = 0; i < cur.size(); i += 2) {
                String l = cur.get(i);
                String r = (i + 1 < cur.size()) ? cur.get(i + 1) : l;
                next.add(parent(l, r));
            }
            cur = next;
            idx /= 2;
        }
        return p;
    }

    /** Verify: caller must also pass position bits; recompute with left/right order by index. */
    public static boolean verify(String leafHex, List<String> proof, int index, String expectedRoot) throws Exception {
        String cur = leafHex.toLowerCase();
        int idx = index;
        for (String sib : proof) {
            cur = (idx % 2 == 0) ? parent(cur, sib.toLowerCase()) : parent(sib.toLowerCase(), cur);
            idx /= 2;
        }
        return cur.equalsIgnoreCase(expectedRoot);
    }
}
