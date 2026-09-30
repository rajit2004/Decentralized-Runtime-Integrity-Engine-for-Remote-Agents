package integrity.agent;

import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Item 13 (open by design, stated): "memory" = whitelisted criticalState map,
 * NOT full heap. Full heap never stabilizes (GC, counters, ASLR).
 * Demo memory attack: POST /tamper/memory?limit=999 or call setLimit().
 */
public final class AgentState {
    private static final AtomicReference<String> limitOverride = new AtomicReference<>(null);

    public static Map<String, String> current() {
        Map<String, String> m = new HashMap<>();
        m.put("mode", "AUTO");
        m.put("limit", limitOverride.get() != null ? limitOverride.get() : "100");
        m.put("version", "3");
        return m;
    }

    /** Simulated memory attack (no file edit). */
    public static void setLimit(String v) { limitOverride.set(v); }
    public static void clearOverride() { limitOverride.set(null); }
}
