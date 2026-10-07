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

    /** All tree levels: get(0) = lowercased leaves, last level = [root]. Build once, prove many. */
    public static List<List<String>> layers(List<String> leaves) throws Exception {
        List<List<String>> out = new ArrayList<>();
        List<String> cur = new ArrayList<>(leaves.size());
        for (String l : leaves) cur.add(l.toLowerCase());
        out.add(cur);
        while (cur.size() > 1) {
            List<String> next = new ArrayList<>((cur.size() + 1) / 2);
            for (int i = 0; i < cur.size(); i += 2) {
                String l = cur.get(i);
                String r = (i + 1 < cur.size()) ? cur.get(i + 1) : l;
                next.add(parent(l, r));
            }
            out.add(next);
            cur = next;
        }
        return out;
    }

    public static String root(List<String> leaves) throws Exception {
        if (leaves.isEmpty()) return Measurer.ZERO_HASH;
        List<List<String>> L = layers(leaves);
        return L.get(L.size() - 1).get(0);
    }

    /** Proof path for leaf index from precomputed layers: O(log n), no tree rebuild. */
    public static List<String> proofFromLayers(List<List<String>> layers, int index) {
        List<String> p = new ArrayList<>();
        int idx = index;
        for (int d = 0; d + 1 < layers.size(); d++) {
            List<String> cur = layers.get(d);
            int sib = (idx % 2 == 0) ? idx + 1 : idx - 1;
            if (sib >= cur.size()) sib = idx; // duplicated odd
            p.add(cur.get(sib));
            idx /= 2;
        }
        return p;
    }

    /** Proof path for leaf index: siblings bottom-up. */
    public static List<String> proof(List<String> leaves, int index) throws Exception {
        if (leaves.isEmpty()) return new ArrayList<>();
        return proofFromLayers(layers(leaves), index);
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
