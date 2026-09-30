package integrity.ui;

import com.sun.net.httpserver.*;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

/** Tiny GREEN/RED page on :8080. JDK only, no deps. */
public final class Dashboard {
    public record Status(String state, String expected, String observed, String chain, String tx, String detail, long cycle) {}

    private final AtomicReference<Status> cur = new AtomicReference<>(
            new Status("STARTING", "-", "-", "-", "-", "boot", 0));

    public void update(Status s) { cur.set(s); }

    public void start(int port) throws IOException {
        HttpServer h = HttpServer.create(new InetSocketAddress(port), 0);
        h.createContext("/", ex -> {
            Status s = cur.get();
            String color = s.state().equals("GREEN") ? "#16a34a" : s.state().equals("RED") ? "#dc2626" : "#ca8a04";
            String html = "<html><body style='font-family:sans-serif;text-align:center'>"
                    + "<h1>Integrity Engine — agent-01</h1>"
                    + "<div style='font-size:64px;color:" + color + "'>" + s.state() + "</div>"
                    + "<p>cycle " + s.cycle() + " | tx " + s.tx() + "</p>"
                    + "<p><b>expected(baseline):</b> " + shortH(s.expected()) + "</p>"
                    + "<p><b>observed(recomputed):</b> " + shortH(s.observed()) + "</p>"
                    + "<p><b>chain:</b> " + shortH(s.chain()) + "</p>"
                    + "<p>" + s.detail() + "</p>"
                    + "<p>Chain proves timeline. Baseline proves goodness. Need both.</p>"
                    + "<meta http-equiv='refresh' content='2'></body></html>";
            byte[] b = html.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "text/html");
            ex.sendResponseHeaders(200, b.length);
            try (OutputStream o = ex.getResponseBody()) { o.write(b); }
        });
        h.start();
        System.out.println("Dashboard on http://localhost:" + port);
    }

    private static String shortH(String h) {
        if (h == null || h.length() < 16) return h;
        return h.substring(0, 12) + "…" + h.substring(h.length() - 6);
    }
}
