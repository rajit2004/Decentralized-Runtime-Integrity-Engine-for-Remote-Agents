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
    static final int LEDGER_ROTATE_AT = 50_000;
    private final String defaultRpc;
    private final Path fallback;
    private final Path cfgPath = Paths.get("config/chain.json");
    public boolean chainUp = false;
    private long localIndex = 0;
    private int ledgerLines;
    private final int ledgerRotateAt;

    private String rpcUrl;
    private String contractAddr; // null = probe-only mode
    private String from;
    private long gas = 1_000_000;
    private boolean enrolled = false;
    // Optional local signing (deploy.js writes privateKey for chainId 31337 only).
    private byte[] rawKey;
    private long chainIdCfg = -1;
    // Baseline pins (item 41): refuse chain mode if chain.json points elsewhere.
    private final String pinnedContract;
    private final String pinnedChainId;
    private Boolean chainIdOk;
    // Hardhat's node 400s Java's default HTTP/2 upgrade attempt - pin HTTP/1.1.
    private final HttpClient http = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(1)).build();

    public ChainAnchor(String rpcUrl, String pinnedContract, String pinnedChainId) {
        this(rpcUrl, pinnedContract, pinnedChainId, Paths.get("ledger.jsonl"), LEDGER_ROTATE_AT);
    }

    /** ledgerFile/ledgerRotateAt injectable for tests; production uses ledger.jsonl @50k. */
    public ChainAnchor(String rpcUrl, String pinnedContract, String pinnedChainId,
                       Path ledgerFile, int ledgerRotateAt) {
        this.defaultRpc = rpcUrl;
        this.rpcUrl = rpcUrl;
        this.fallback = ledgerFile;
        this.ledgerRotateAt = ledgerRotateAt;
        this.pinnedContract = pinnedContract == null ? "" : pinnedContract;
        this.pinnedChainId = pinnedChainId == null ? "" : pinnedChainId;
        try { if (Files.exists(fallback)) ledgerLines = Files.readAllLines(fallback).size(); }
        catch (Exception ignored) { ledgerLines = 0; }
        loadConfig();
        if (contractAddr != null && !pinMatches(this.pinnedContract, contractAddr)) {
            System.out.println("CHAIN PIN: contract mismatch pinned=" + this.pinnedContract
                    + " configured=" + contractAddr + " -> chain mode refused, ledger fallback");
            contractAddr = null;
        }
    }

    /** Absent pin = open (fresh-clone friendly); present pin must match case-insensitively. */
    public static boolean pinMatches(String pinned, String live) {
        if (pinned == null || pinned.isEmpty()) return true;
        return live != null && live.equalsIgnoreCase(pinned);
    }

    public record AnchorReceipt(String ledgerRef, boolean fromChain, long chainTs, Abi.ChainRecord chainRec) {}

    /** RPC precedence: RPC_URL env > config/chain.json rpcUrl > constructor default. */
    public static String pickRpc(String env, String chainJsonVal, String def) {
        if (env != null && !env.isBlank()) return env.trim();
        if (chainJsonVal != null && !chainJsonVal.isBlank()) return chainJsonVal;
        return def;
    }

    /** config/chain.json: {"rpcUrl":"...","contractAddr":"0x..","from":"0x..","gas":"0x.."} (optional). */
    private void loadConfig() {
        String jsonRpc = "";
        try {
            if (Files.exists(cfgPath)) {
                String j = Files.readString(cfgPath);
                if (j.contains("\"rpcUrl\"")) jsonRpc = Verifier.get(j, "rpcUrl");
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
                if (j.contains("\"privateKey\"")) {
                    String k = Verifier.get(j, "privateKey");
                    if (!k.isBlank()) {
                        try {
                            byte[] key = Secp256k1.unhex(k);
                            if (key.length == 32) this.rawKey = key;
                        } catch (Exception ignored) { this.rawKey = null; }
                    }
                }
                if (j.contains("\"chainId\"")) {
                    String c = Verifier.get(j, "chainId");
                    if (!c.isBlank()) {
                        try {
                            this.chainIdCfg = Long.parseLong(c.startsWith("0x") ? c.substring(2) : c,
                                    c.startsWith("0x") ? 16 : 10);
                        } catch (Exception ignored) { this.chainIdCfg = -1; }
                    }
                }
            }
        } catch (Exception ignored) { /* probe-only mode */ }
        this.rpcUrl = pickRpc(System.getenv("RPC_URL"), jsonRpc, defaultRpc);
        if (rawKey != null)
            System.out.println("RAW TX: local secp256k1 signing enabled (privateKey from config/chain.json, dev chain only)");
    }

    public boolean configured() { return contractAddr != null; }

    /** Live eth_chainId must equal the baseline pin; verified once per boot. */
    private boolean chainIdVerified() {
        if (pinnedChainId == null || pinnedChainId.isEmpty()) return true;
        if (chainIdOk != null) return chainIdOk;
        String live = rpc("eth_chainId", "[]", 2000);
        chainIdOk = pinMatches(pinnedChainId, live);
        if (!chainIdOk)
            System.out.println("CHAIN PIN: chainId mismatch pinned=" + pinnedChainId
                    + " live=" + live + " -> chain mode refused, ledger fallback");
        return chainIdOk;
    }

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
        if (rawKey != null) return sendRawTx(data);
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

    /** EIP-155 chainId for signing: baseline pin wins over config/chain.json. */
    private long signChainId() {
        if (pinnedChainId != null && !pinnedChainId.isEmpty()) {
            try {
                return Long.parseLong(pinnedChainId.startsWith("0x") ? pinnedChainId.substring(2) : pinnedChainId,
                        pinnedChainId.startsWith("0x") ? 16 : 10);
            } catch (Exception ignored) { /* fall through to config */ }
        }
        return chainIdCfg;
    }

    /** Local sign: nonce + gasPrice from the node, secp256k1 EIP-155, eth_sendRawTransaction.
     *  One immediate retry covers a lost/slow response: each attempt fetches the current
     *  pending nonce, so a tx that already landed gets a higher nonce (duplicate-seq txs
     *  revert on prevHash break, chain state stays correct), a never-arrived tx is resent. */
    private String sendRawTx(String data) {
        try {
            String fromAddr = Secp256k1.addressHex(rawKey);
            String r = rawAttempt(fromAddr, data);
            if (r == null) {
                Thread.sleep(250);
                r = rawAttempt(fromAddr, data);
            }
            return r;
        } catch (Exception e) {
            System.out.println("RAW_TX_ERR " + e);
            return null;
        }
    }

    private String rawAttempt(String fromAddr, String data) {
        try {
            String nonceHex = rpc("eth_getTransactionCount", "[\"" + fromAddr + "\",\"pending\"]", 2000);
            String gasHex = rpc("eth_gasPrice", "[]", 2000);
            long chainId = signChainId();
            if (nonceHex == null || !nonceHex.startsWith("0x")) return null;
            if (gasHex == null || !gasHex.startsWith("0x")) return null;
            if (chainId <= 0) return null;
            long nonce = Long.parseLong(nonceHex.substring(2), 16);
            long gasPrice = Long.parseLong(gasHex.substring(2), 16);
            byte[] to = Secp256k1.unhex(contractAddr);
            byte[] payload = Secp256k1.unhex(data);
            byte[] unsigned = Rlp.unsignedLegacy(nonce, gasPrice, gas, to, 0, payload, chainId);
            byte[] z = Keccak.keccak256(unsigned);
            Secp256k1.Sig sig = Secp256k1.sign(rawKey, z, chainId);
            byte[] tx = Rlp.signedLegacy(nonce, gasPrice, gas, to, 0, payload, sig.v(), sig.r(), sig.s());
            String r = rpc("eth_sendRawTransaction", "[\"0x" + Abi.hex(tx) + "\"]", 3000);
            if (r == null || !r.startsWith("0x") || r.startsWith("ERROR")) return null;
            return r;
        } catch (Exception e) { return null; }
    }

    /** Wait for automined receipt; returns "0x1", "0x0", or null (still pending).
     *  Adaptive: fast-first (automined receipts usually land instantly), then back off.
     *  10 x 50ms + 3 x 200ms ~= 1.1s worst case (was 6 x 200ms = 1.2s with a slow first retry). */
    private String receiptStatus(String txHash) {
        for (int i = 0; i < 13; i++) {
            String body = rpcRawResult("eth_getTransactionReceipt", "[\"" + txHash + "\"]", 2000);
            if (body != null && body.contains("\"status\":\"0x0\"")) return "0x0";
            if (body != null && body.contains("\"status\":\"0x1\"")) return "0x1";
            try { Thread.sleep(i < 10 ? 50 : 200); }
            catch (InterruptedException ie) { Thread.currentThread().interrupt(); return null; }
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

    /** eth_call getLatest + decode. null = RPC/decode trouble, caller degrades to no-readback. */
    public Abi.ChainRecord readLatest(String agentId) {
        String r = rpc("eth_call", "[{\"to\":\"" + contractAddr + "\",\"data\":\"0x"
                + Abi.hex(Abi.encGetLatest(agentId)) + "\"},\"latest\"]", 2000);
        if (r == null || !r.startsWith("0x")) return null;
        return Abi.decodeLatest(r);
    }

    public AnchorReceipt anchor(SignedMeasurement m) {
        chainUp = probe();
        String ref;
        boolean onChain = false;
        long chainTs = -1;
        Abi.ChainRecord chainRec = null;

        if (chainUp && configured() && chainIdVerified()) {
            try {
                long count = anchorCount(m.agentId());
                // eth_call invalid or address has no code: refuse to send a
                // phantom tx (txs to code-less addresses "succeed" as 0x1).
                if (count < 0) {
                    ref = "local-" + (++localIndex) + "(no-contract)";
                    return finish(m, ref, false, -1, null);
                }
                if (count == 0 && !enrolled) {
                    // Phase 0 on-chain: chain head := our prevHash so first anchor links.
                    String en = sendTx(Abi.hex(Abi.encEnroll(m.agentId(), m.hBin(), m.hCfg(), m.hMem(), m.prevHash())));
                    if (en != null) {
                        String st = receiptStatus(en);
                        if (confirmed(st)) enrolled = true;
                        else if ("0x0".equals(st)) { ref = "local-" + (++localIndex) + "(enroll-revert)"; return finish(m, ref, false, -1, null); }
                        else { ref = "local-" + (++localIndex) + "(enroll-pending)"; return finish(m, ref, false, -1, null); }
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
                        // Authoritative readback: Boss verifies what the chain STORED,
                        // not just what we submitted (review item 37).
                        chainRec = readLatest(m.agentId());
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
        } else if (chainUp && configured()) {
            // pinned chainId != live chainId: refuse to anchor on the wrong chain.
            ref = "local-" + (++localIndex) + "(chainid-refused)";
        } else if (chainUp) {
            // probe-only: node reachable but contract not configured (no fake tx hash).
            ref = "chain-unconfigured";
            chainTs = fetchChainTs();
        } else {
            ref = "local-" + (++localIndex);
        }
        return finish(m, ref, onChain, chainTs, chainRec);
    }

    private AnchorReceipt finish(SignedMeasurement m, String ref, boolean onChain, long chainTs, Abi.ChainRecord chainRec) {
        try {
            Files.writeString(fallback, withRef(m, ref) + "\n",
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            // Rotation: archive at threshold; a fresh active file just starts empty
            // (boot resume falls back to baseline + config/seq.dat, same as fresh clone).
            if (++ledgerLines >= ledgerRotateAt) {
                Path archive = fallback.resolveSibling(fallback.getFileName() + "." + System.currentTimeMillis());
                Files.move(fallback, archive, StandardCopyOption.REPLACE_EXISTING);
                ledgerLines = 0;
                System.out.println("LEDGER rotated -> " + archive.getFileName());
            }
        } catch (IOException ignored) {}
        return new AnchorReceipt(ref, onChain, chainTs, chainRec);
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
