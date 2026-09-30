package integrity.measure;

/**
 * Frozen wire format Checker -> Verifier (also ledger + dashboard).
 * {"agentId","seq","ts","hBin","hCfg","hMem","hComb","prevHash","sig","ledgerRef"}
 * Manual JSON, no libs. All hashes 64-char lowercase hex. ts = Unix seconds.
 * prevHash = previous hComb, genesis = 64 zeros.
 */
public record SignedMeasurement(
        String agentId, long seq, long ts,
        String hBin, String hCfg, String hMem, String hComb, String prevHash,
        String sig, String ledgerRef) {

    public String toJson() {
        return "{\"agentId\":\"" + agentId + "\",\"seq\":" + seq + ",\"ts\":" + ts
                + ",\"hBin\":\"" + hBin + "\",\"hCfg\":\"" + hCfg + "\",\"hMem\":\"" + hMem
                + "\",\"hComb\":\"" + hComb + "\",\"prevHash\":\"" + prevHash
                + "\",\"sig\":\"" + sig + "\",\"ledgerRef\":\"" + ledgerRef + "\"}";
    }
}
