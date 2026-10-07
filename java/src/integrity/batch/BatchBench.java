package integrity.batch;

import integrity.measure.Measurer;
import java.security.MessageDigest;
import java.util.*;

/**
 * Benchmark for the batch path: builds 10k-leaf tree, proves + verifies one leaf.
 * Run: java -cp out integrity.batch.BatchBench
 * Math printed: naive TPS vs batched TPS + build/verify ms.
 */
public final class BatchBench {
    public static void main(String[] args) throws Exception {
        int n = args.length > 0 ? Integer.parseInt(args[0]) : 10000;
        MessageDigest d = MessageDigest.getInstance("SHA-256");
        List<String> leaves = new ArrayList<>(n);
        Random rnd = new Random(42);
        for (int i = 0; i < n; i++) {
            byte[] b = new byte[32];
            rnd.nextBytes(b);
            StringBuilder sb = new StringBuilder(64);
            for (byte x : b) sb.append(String.format("%02x", x));
            leaves.add(sb.toString());
        }
        long t0 = System.nanoTime();
        String root = MerkleTree.root(leaves);
        long t1 = System.nanoTime();
        int idx = n / 2;
        List<String> proof = MerkleTree.proof(leaves, idx);
        long t2 = System.nanoTime();
        boolean ok = MerkleTree.verify(leaves.get(idx), proof, idx, root);
        long t3 = System.nanoTime();
        // also show leaf-comb rule sanity
        String demo = Measurer.combine(leaves.get(0), leaves.get(1 % n), leaves.get(2 % n));

        double naiveTps = n / 5.0;          // 10k devices, 5s heartbeat
        double batchedTps = 1.0 / 60.0;     // 1 root per minute
        System.out.println("leaves=" + n + " root=" + root.substring(0, 16) + "... proofLen=" + proof.size() + " verify=" + ok);
        System.out.println("buildMs=" + ((t1 - t0) / 1_000_000) + " proofMs=" + ((t2 - t1) / 1_000_000) + " verifyMs=" + ((t3 - t2) / 1_000_000));
        System.out.println("naive=" + naiveTps + " TPS vs batched=" + batchedTps + " TPS reduction=" + (naiveTps / batchedTps) + "x");
        System.out.println("demoCombine=" + demo.substring(0, 16) + "...");
        System.out.println("ZERO=" + Measurer.ZERO_HASH.substring(0, 8) + "...");
    }
}
