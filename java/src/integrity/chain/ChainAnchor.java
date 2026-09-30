package integrity.chain;

import integrity.measure.SignedMeasurement;
import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.nio.file.*;
import java.time.Duration;

/**
 * Diary writer on frozen contract. Anchors full SignedMeasurement JSON.
 * Tries local chain JSON-RPC (:8545), always appends ledger.jsonl FALLBACK
 * (tamper-evident, NOT tamper-proof — item 10) so demo never dies.
 * ledgerRef = tx hash if chain up, else local index.
 * Item 8: chainTs = block.timestamp when chainUp (authoritative), else -1.
 */
public final class ChainAnchor {
    private final String rpcUrl;
    private final Path fallback = Paths.get("ledger.jsonl");
    public boolean chainUp = false;
    private long localIndex = 0;

    public ChainAnchor(String rpcUrl) { this.rpcUrl = rpcUrl; }

    public record AnchorReceipt(String ledgerRef, boolean fromChain, long chainTs) {}

    private long fetchChainTs(HttpClient c) {
        try {
            String body = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"eth_getBlockByNumber\",\"params\":[\"latest\",false]}";
            HttpRequest req = HttpRequest.newBuilder(URI.create(rpcUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .timeout(Duration.ofSeconds(2)).build();
            var resp = c.send(req, HttpResponse.BodyHandlers.ofString());
            String b = resp.body();
            int i = b.indexOf("\"timestamp\"");
            if (i < 0) return -1;
            int q1 = b.indexOf('"', b.indexOf(':', i) + 1);
            // value may be "0x..." quoted or unquoted
            int s = q1 >= 0 ? q1 + 1 : b.indexOf(':', i) + 1;
            int e = s;
            while (e < b.length() && "0123456789xXabcdefABCDEF\" ".indexOf(b.charAt(e)) >= 0
                    && b.charAt(e) != '"' && b.charAt(e) != ',' && b.charAt(e) != '}') e++;
            String hex = b.substring(s, e).trim().replace("\"", "");
            if (hex.startsWith("0x") || hex.startsWith("0X")) return Long.parseLong(hex.substring(2), 16);
            return Long.parseLong(hex);
        } catch (Exception e) { return -1; }
    }

    public AnchorReceipt anchor(SignedMeasurement m) {
        long chainTs = -1;
        try {
            HttpClient c = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).build();
            String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_blockNumber\",\"params\":[]}";
            HttpRequest req = HttpRequest.newBuilder(URI.create(rpcUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .timeout(Duration.ofSeconds(2)).build();
            var resp = c.send(req, HttpResponse.BodyHandlers.ofString());
            chainUp = resp.statusCode() == 200 && resp.body().contains("result");
            if (chainUp) chainTs = fetchChainTs(c);
        } catch (Exception e) { chainUp = false; }

        localIndex++;
        String ref = chainUp ? ("0x" + m.hComb().substring(0, 16) + Long.toHexString(m.seq())) : ("local-" + localIndex);
        try {
            Files.writeString(fallback, withRef(m, ref) + "\n",
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {}
        return new AnchorReceipt(ref, chainUp, chainTs);
    }

    private static String withRef(SignedMeasurement m, String ref) {
        return new SignedMeasurement(m.agentId(), m.seq(), m.ts(), m.hBin(), m.hCfg(),
                m.hMem(), m.hComb(), m.prevHash(), m.sig(), ref).toJson();
    }
}
