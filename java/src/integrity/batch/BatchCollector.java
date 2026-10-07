package integrity.batch;

import java.util.*;

/**
 * One window of device hashes -> one root. Demo: 12 heartbeats (60s @5s) or
 * N simulated devices. Caller anchors root/min via ChainAnchor/contract,
 * stores proofs per device. Single-device demo keeps running as today;
 * batch path proves scale without 2000 TPS.
 */
public final class BatchCollector {
    private final List<String> agentIds = new ArrayList<>();
    private final List<String> leaves = new ArrayList<>();

    public void add(String agentId, String hCombHex) {
        agentIds.add(agentId);
        leaves.add(hCombHex.toLowerCase());
    }

    public int size() { return leaves.size(); }

    public String root() throws Exception { return MerkleTree.root(leaves); }

    public Map<String, List<String>> proofs() throws Exception {
        Map<String, List<String>> out = new LinkedHashMap<>();
        List<List<String>> L = MerkleTree.layers(leaves);
        for (int i = 0; i < leaves.size(); i++) out.put(agentIds.get(i), MerkleTree.proofFromLayers(L, i));
        return out;
    }

    public void clear() { agentIds.clear(); leaves.clear(); }
}
