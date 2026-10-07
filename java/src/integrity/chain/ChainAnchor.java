package integrity.chain;

import integrity.measure.SignedMeasurement;
import integrity.verify.Verifier;
import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.nio.file.*;
import java.time.Duration;

/**
 * Diary writer on frozen contract. Anchors full SignedMeasurement JSON.
 *
 * When config/chain.json exists (written by contract/scripts/deploy.js) and the
 * node is up, we REALLY anchor on-chain: enroll() once (anchorCount==0), then
 * anchor() every cycle via eth_sendTransaction from an unlocked local account.
 * ledgerRef becomes the real tx hash and block.timestamp becomes the
 * authoritative effectiveTs (fromChain=true only after a mined success).
 *
 * Otherwise: probe liveness only + append ledger.jsonl FALLBACK (tamper-evident,
 * NOT tamper-proof) so the demo never dies. Item 8: chainTs = block.timestamp
 * when chainUp, else -1.
 */
public final class ChainAnchor {
    private final String defaultRpc;
    private final Path fallback = Paths.get("ledger.jsonl");
    private final Path cfgPath = Paths.get("config/chain.json");
    public boolean chainUp = false;
    private long localIndex = 0;

    private String rpcUrl;
    private String contractAddr; // null = probe-only mode
    private String from;
    private long gas = 1_000_000;
    private boolean enrolled = false;
    // Hardhat's node 400s Java's default HTTP/2 upgrade attempt - pin HTTP/1.1.
    private final HttpClient http = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(1)).build();

    public ChainAnchor(String rpcUrl) {
        this.defaultRpc = rpcUrl;
        this.rpcUrl = rpcUrl;
        loadConfig();
    }

    public record AnchorReceipt(String ledgerRef, boolean fromChain, long chainTs) {}

    /** config/chain.json: {"rpcUrl":"...","contractAddr":"0x..","from":"0x..","gas":"0x.."} (optional). */
    private void loadConfig() {
        try {
            if (!Files.exists(cfgPath)) return;
            String j = Files.readString(cfgPath);
            if (j.contains("\"rpcUrl\"")) {
                String rpc = Verifier.get(j, "rpcUrl");
                if (!rpc.isBlank()) this.rpcUrl = rpc;
            }
            if (j.contains("\"contractAddr\"")) {
                String addr = Verifier.get(j, "contractAddr");
                if (!addr.isBlank()) this.contractAddr = addr;
            }
            if (j.contains("\"from\"")) {
                String f = Verifier.get(j, "from");
                if (!f.isBlank()) this.from = f;
            }
            if (j.contains("\"gas\"")) {
                String g = Verifier.get(j, "gas");
                if (!g.isBlank()) this.gas = Long.parseLong(g.startsWith("0x") ? g.substring(2) : g, g.startsWith("0x") ? 16 : 10);
            }
        } catch (Exception ignored) { /* probe-only mode */ }
    }

    public boolean configured() { return contractAddr != null; }

    // ---- raw JSON-RPC helpers (no web3j) ----

    private String rpc(String method, String paramsJson, long timeoutMs) {
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" + method + "\",\"params\":" + paramsJson + "}";
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(rpcUrl))
                    .version(HttpClient.Version.HTTP_1_1)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .timeout(Duration.ofMillis(timeoutMs)).build();
            var resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) return null;
            String b = resp.body();
            if (b.contains("\"error\"")) return "ERROR:" + b;
            int i = b.indexOf("\"result\"");
            if (i < 0) return null;
            int q1 = b.indexOf('"', b.indexOf(':', i) + 1);
            if (q1 < 0) return null; // result may be null
            int q2 = b.indexOf('"', q1 + 1);
            return b.substring(q1 + 1, q2);
        } catch (Exception e) { return null; }
    }

    private String rpcRawResult(String method, String paramsJson, long timeoutMs) {
        // captures object results (e.g. receipts) as JSON text
        String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"" + method + "\",\"params\":" + paramsJson + "}";
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(rpcUrl))
                    .version(HttpClient.Version.HTTP_1_1)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .timeout(Duration.ofMillis(timeoutMs)).build();
            var resp = http.send(req, HttpResponse.BodyHandlers.ofString());
            return resp.statusCode() == 200 ? resp.body() : null;
        } catch (Exception e) { return null; }
    }

    private long fetchChainTs() {
        String r = rpcRawResult("eth_getBlockByNumber", "[\"latest\",false]", 2000);
        if (r == null || r.contains("\"error\"")) return -1;
        int i = r.indexOf("\"timestamp\"");
        if (i < 0) return -1;
        int s = r.indexOf(':', i) + 1;
        while (s < r.length() && (r.charAt(s) == ' ' || r.charAt(s) == '"')) s++;
        int e = s;
        while (e < r.length() && "0123456789abcdefABCDEF".indexOf(r.charAt(e)) >= 0) e++;
        try { return Long.parseLong(r.substring(s, e).replace("\"", ""), 16); }
        catch (Exception ex) { return -1; }
    }

    private String sendTx(String data) {
        if (from == null) {
            String a = rpc("eth_accounts", "[]", 2000);
            if (a == null || !a.startsWith("0x")) return null;
            from = a.length() >= 42 ? a.substring(0, 42) : a;
        }
        String nonceHex = rpc("eth_getTransactionCount", "[\"" + from + "\",\"pending\"]", 2000);
        String noncePart = (nonceHex != null && nonceHex.startsWith("0x"))
                ? ",\"nonce\":\"" + nonceHex + "\"" : "";
        String params = "[{\"from\":\"" + from + "\",\"to\":\"" + contractAddr + "\""
                + ",\"gas\":\"0x" + Long.toHexString(gas) + "\"" + noncePart
                + ",\"data\":\"0x" + data + "\"}]";
        String r = rpc("eth_sendTransaction", params, 3000);
        if (r == null || !r.startsWith("0x") || r.startsWith("ERROR")) return null;
        return r;
    }

    /** Wait briefly for automined receipt; returns "0x1", "0x0", or null (still pending). */
    private String receiptStatus(String txHash) {
        for (int i = 0; i < 6; i++) {
            String body = rpcRawResult("eth_getTransactionReceipt", "[\"" + txHash + "\"]", 2000);
            if (body != null && body.contains("\"status\":\"0x0\"")) return "0x0";
            if (body != null && body.contains("\"status\":\"0x1\"")) return "0x1";
            try { Thread.sleep(200); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); return null; }
        }
        return null;
    }

    /** Only a mined 0x1 receipt counts as success. null = pending/unknown, "0x0" = reverted. */
    public static boolean confirmed(String status) { return "0x1".equals(status); }

    private byte[] agentKey(String agentId) {
        return Keccak.keccak256(agentId.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private long anchorCount(String agentId) {
        String r = rpc("eth_call", "[{\"to\":\"" + contractAddr + "\",\"data\":\"0x"
                + Abi.hex(Abi.encAnchorCount(agentKey(agentId))) + "\"},\"latest\"]", 2000);
        if (r == null || !r.startsWith("0x") || r.length() < 3) return -1;
        try { return new java.math.BigInteger(r.substring(2), 16).longValueExact(); }
        catch (Exception e) { return -1; }
    }

    // ---- anchor ----

    public AnchorReceipt anchor(SignedMeasurement m) {
        chainUp = probe();
        String ref;
        boolean onChain = false;
        long chainTs = -1;

        if (chainUp && configured()) {
            try {
                long count = anchorCount(m.agentId());
                if (count == 0 && !enrolled) {
                    // Phase 0 on-chain: chain head := our prevHash so first anchor links.
                    String en = sendTx(Abi.hex(Abi.encEnroll(m.agentId(), m.hBin(), m.hCfg(), m.hMem(), m.prevHash())));
                    if (en != null) {
                        String st = receiptStatus(en);
                        if (confirmed(st)) enrolled = true;
                        else if ("0x0".equals(st)) { ref = "local-" + (++localIndex) + "(enroll-revert)"; return finish(m, ref, false, -1); }
                        else { ref = "local-" + (++localIndex) + "(enroll-pending)"; return finish(m, ref, false, -1); }
                    }
                } else if (count > 0) {
                    enrolled = true;
                }
                String tx = sendTx(Abi.hex(Abi.encAnchor(m.agentId(), m.seq(), m.hBin(), m.hCfg(),
                        m.hMem(), m.hComb(), m.prevHash(), Base64decode(m.sig()))));
                if (tx != null) {
                    String st = receiptStatus(tx);
                    if (confirmed(st)) {
                        ref = tx;
                        onChain = true;
                        chainTs = fetchChainTs();
                    } else if ("0x0".equals(st)) {
                        ref = "local-" + (++localIndex) + "(anchor-revert)";
                    } else {
                        ref = "local-" + (++localIndex) + "(anchor-pending)";
                    }
                } else {
                    ref = "local-" + (++localIndex) + "(send-fail)";
                }
            } catch (Exception e) {
                ref = "local-" + (++localIndex) + "(chain-err)";
            }
        } else if (chainUp) {
            // probe-only: node reachable but contract not configured (no fake tx hash).
            ref = "chain-unconfigured";
            chainTs = fetchChainTs();
        } else {
            ref = "local-" + (++localIndex);
        }
        return finish(m, ref, onChain, chainTs);
    }

    private AnchorReceipt finish(SignedMeasurement m, String ref, boolean onChain, long chainTs) {
        try {
            Files.writeString(fallback, withRef(m, ref) + "\n",
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {}
        return new AnchorReceipt(ref, onChain, chainTs);
    }

    private boolean probe() {
        try {
            String r = rpc("eth_blockNumber", "[]", 2000);
            return r != null && r.startsWith("0x");
        } catch (Exception e) { return false; }
    }

    private static byte[] Base64decode(String sigB64) {
        try { return java.util.Base64.getDecoder().decode(sigB64); }
        catch (Exception e) { return new byte[0]; }
    }

    private static String withRef(SignedMeasurement m, String ref) {
        return new SignedMeasurement(m.agentId(), m.seq(), m.ts(), m.hBin(), m.hCfg(),
                m.hMem(), m.hComb(), m.prevHash(), m.sig(), ref).toJson();
    }
}
