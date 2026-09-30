package integrity.chain;

import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.nio.file.*;
import java.time.Duration;

/**
 * Diary writer. Tries local chain JSON-RPC (Anvil/Hardhat on :8545),
 * falls back to local append-only ledger.jsonl so demo never dies.
 * Chain proves timeline, NOT goodness (see baseline).
 */
public final class ChainAnchor {
    private final String rpcUrl;
    private final Path fallback = Paths.get("ledger.jsonl");
    public boolean chainUp = false;

    public ChainAnchor(String rpcUrl) { this.rpcUrl = rpcUrl; }

    public record AnchorReceipt(String txHash, long blockNum, boolean fromChain) {}

    public AnchorReceipt anchor(String agentId, String hComb, long nonce, String sigB64) {
        // Minimal: store event locally + try eth_blockNumber to detect chain liveness.
        // Full contract call via ethers is done by Node sidecar; Java records intent.
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

        String line = System.currentTimeMillis() + " agent=" + agentId + " hComb=" + hComb
                + " nonce=" + nonce + " chainUp=" + chainUp + "\n";
        try { Files.writeString(fallback, line, java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND); }
        catch (IOException ignored) {}
        String fakeTx = "0x" + hComb.substring(0, 16) + Long.toHexString(nonce);
        return new AnchorReceipt(fakeTx, -1, chainUp);
    }
}
