package integrity.ui;

import com.sun.net.httpserver.*;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Interactive dashboard on :8080. JDK only, zero CDN (offline-safe).
 * Serves web/index.html + app.js + styles.css from web/ dir (falls back to
 * embedded page if missing), plus JSON APIs polled by the frontend:
 *   GET /api/status  -> latest Status as JSON
 *   GET /api/history -> last 60 cycles as JSON array
 *   GET /api/tamper/config   -> flip threshold 100->999 (demo attack)
 *   GET /api/restore/config  -> restore threshold (re-enroll if line endings shift)
 */
public final class Dashboard {
    public record Status(String state, long seq, String component, String verdict,
                         String expected, String observed, String chain, String prevHash,
                         String tx, String detail, long cycle,
                         long measureMs, long verifyMs, boolean chainUp) {}

    private final AtomicReference<Status> cur = new AtomicReference<>(
            new Status("STARTING", 0, "-", "-", "-", "-", "-", "-", "-", "boot", 0, 0, 0, false));
    private final Deque<Status> history = new ArrayDeque<>();
    private final Path webDir = Paths.get("web");

    public synchronized void update(Status s) {
        cur.set(s);
        history.addLast(s);
        while (history.size() > 60) history.removeFirst();
    }

    public HttpServer start(int port) throws IOException {
        HttpServer h = HttpServer.create(new InetSocketAddress(port), 0);
        h.createContext("/", ex -> {
            String path = ex.getRequestURI().getPath();
            if (path.equals("/") || path.equals("/index.html")) serveFile(ex, "index.html", "text/html", true);
            else if (path.equals("/app.js")) serveFile(ex, "app.js", "application/javascript", false);
            else if (path.equals("/styles.css")) serveFile(ex, "styles.css", "text/css", false);
            else if (path.equals("/api/status")) serveJson(ex, statusJson(cur.get()));
            else if (path.equals("/api/history")) serveJson(ex, historyJson());
            else if (path.equals("/api/baseline")) serveBaseline(ex);
            else if (path.equals("/api/tamper/config")) serveJson(ex, tamperConfig());
            else if (path.equals("/api/restore/config")) serveJson(ex, restoreConfig());
            else { byte[] b = "not found".getBytes(StandardCharsets.UTF_8); ex.sendResponseHeaders(404, b.length);
                try (OutputStream o = ex.getResponseBody()) { o.write(b); } }
        });
        h.start();
        System.out.println("Dashboard on http://localhost:" + port);
        return h;
    }

    // ---- page + static ----

    private void serveFile(HttpExchange ex, String name, String type, boolean fallback) throws IOException {
        Path f = webDir.resolve(name);
        byte[] b;
        if (Files.exists(f)) b = Files.readAllBytes(f);
        else if (fallback) b = embeddedPage().getBytes(StandardCharsets.UTF_8);
        else { b = ("/* missing web/" + name + " */").getBytes(StandardCharsets.UTF_8); }
        ex.getResponseHeaders().add("Content-Type", type + "; charset=utf-8");
        ex.sendResponseHeaders(200, b.length);
        try (OutputStream o = ex.getResponseBody()) { o.write(b); }
    }

    private void serveJson(HttpExchange ex, String json) throws IOException {
        byte[] b = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().add("Cache-Control", "no-store");
        ex.sendResponseHeaders(200, b.length);
        try (OutputStream o = ex.getResponseBody()) { o.write(b); }
    }

    private String embeddedPage() {
        Status s = cur.get();
        return "<html><body style='background:#0b1220;color:#e5e7eb;font-family:sans-serif;text-align:center'>"
                + "<h1>Integrity Engine</h1><h2>" + esc(s.state()) + "</h2>"
                + "<p>Full UI missing: restore web/ dir. API: <a href='/api/status'>/api/status</a></p></body></html>";
    }

    // ---- JSON ----

    static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("<", "&lt;");
    }

    String statusJson(Status s) {
        return "{\"state\":\"" + s.state() + "\",\"seq\":" + s.seq() + ",\"cycle\":" + s.cycle()
                + ",\"verdict\":\"" + s.verdict() + "\",\"component\":\"" + s.component() + "\""
                + ",\"expected\":\"" + s.expected() + "\",\"observed\":\"" + s.observed() + "\""
                + ",\"chain\":\"" + s.chain() + "\",\"prevHash\":\"" + s.prevHash() + "\""
                + ",\"tx\":\"" + esc(s.tx()) + "\",\"detail\":\"" + esc(s.detail()) + "\""
                + ",\"measureMs\":" + s.measureMs() + ",\"verifyMs\":" + s.verifyMs()
                + ",\"chainUp\":" + s.chainUp() + ",\"now\":" + (System.currentTimeMillis() / 1000) + "}";
    }

    synchronized String historyJson() {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (Status s : history) {
            if (!first) sb.append(",");
            first = false;
            sb.append("{\"seq\":").append(s.seq()).append(",\"cycle\":").append(s.cycle())
              .append(",\"state\":\"").append(s.state()).append("\",\"verdict\":\"").append(s.verdict())
              .append("\",\"component\":\"").append(s.component()).append("\",\"tx\":\"").append(esc(s.tx()))
              .append("\",\"expected\":\"").append(s.expected()).append("\",\"observed\":\"").append(s.observed())
              .append("\",\"chain\":\"").append(s.chain()).append("\",\"prevHash\":\"").append(s.prevHash())
              .append("\",\"detail\":\"").append(esc(s.detail()))
              .append("\",\"measureMs\":").append(s.measureMs()).append(",\"verifyMs\":").append(s.verifyMs())
              .append(",\"chainUp\":").append(s.chainUp()).append("}");
        }
        return sb.append("]").toString();
    }

    private final Path baselinePath = Paths.get("config/baseline.json");

    private void serveBaseline(HttpExchange ex) throws IOException {
        try {
            serveJson(ex, Files.readString(baselinePath));
        } catch (Exception e) {
            serveJson(ex, "{\"ok\":false,\"msg\":\"no baseline enrolled yet\"}");
        }
    }

    // ---- one-click demo attacks (config file tamper + restore) ----

    private final Path cfgPath = Paths.get("config/agent-config.json");

    synchronized String tamperConfig() {
        try {
            String c = Files.readString(cfgPath);
            if (!c.contains("\"threshold\": 999")) {
                Files.writeString(cfgPath, c.replace("\"threshold\": 100", "\"threshold\": 999"));
                return "{\"ok\":true,\"msg\":\"config tampered 100->999, watch for POLICY_CFG_CHANGED\"}";
            }
            return "{\"ok\":true,\"msg\":\"already tampered\"}";
        } catch (Exception e) { return "{\"ok\":false,\"msg\":\"" + esc(e.toString()) + "\"}"; }
    }

    synchronized String restoreConfig() {
        try {
            String c = Files.readString(cfgPath);
            Files.writeString(cfgPath, c.replace("\"threshold\": 999", "\"threshold\": 100"));
            return "{\"ok\":true,\"msg\":\"config restored 999->100. If still RED, re-run Enroll-Baseline (line endings shift hashes).\"}";
        } catch (Exception e) { return "{\"ok\":false,\"msg\":\"" + esc(e.toString()) + "\"}"; }
    }

    public static String shortH(String h) {
        if (h == null || h.length() < 16) return h == null ? "-" : h;
        return h.substring(0, 12) + "…" + h.substring(h.length() - 6);
    }
}
