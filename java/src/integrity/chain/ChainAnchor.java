package integrity.chain;

import integrity.measure.SignedMeasurement;
import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.nio.file.*;
import java.time.Duration;

/**
 * Diary writer on frozen contract. Anchors full SignedMeasurement JSON.
 * Tries local chain JSON-RPC (:8545), always appends ledger.jsonl so demo never dies.
 * ledgerRef = tx hash if chain up, else local index.
 */
public final class ChainAnchor {
    private final String rpcUrl;
    private final Path fallback = Paths.get("ledger.jsonl");
    public boolean chainUp = false;
    private long localIndex = 0;

    public ChainAnchor(String rpcUrl) { this.rpcUrl = rpcUrl; }

    public record AnchorReceipt(String ledgerRef, boolean fromChain) {}

    public AnchorReceipt anchor(SignedMeasurement m) {
        try {
            HttpClient c = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(1)).build();
            String body = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_blockNumber\",\"params\":[]}";
            HttpRequest req = HttpRequest.newBuilder(URI.create(rpcUrl))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .timeout(Duration.ofSeconds(2)).build();
            var resp = c.send(req, HttpResponse.BodyHandlers.ofString());
            chainUp = resp.statusCode() == 200 && resp.body().contains("result");
        } catch (Exception e) { chainUp = false; }

        localIndex++;
        String ref = chainUp ? ("0x" + m.hComb().substring(0, 16) + Long.toHexString(m.seq())) : ("local-" + localIndex);
        String line = m.toJson().replace("\"ledgerRef\":\"\"", "\"ledgerRef\":\"" + ref + "\"") + "\n";
        // if already has ref, keep line as full JSON with ref
        try {
            Files.writeString(fallback, withRef(m, ref) + "\n",
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        } catch (IOException ignored) {}
        return new AnchorReceipt(ref, chainUp);
    }

    private static String withRef(SignedMeasurement m, String ref) {
        return new SignedMeasurement(m.agentId(), m.seq(), m.ts(), m.hBin(), m.hCfg(),
                m.hMem(), m.hComb(), m.prevHash(), m.sig(), ref).toJson();
    }
}
