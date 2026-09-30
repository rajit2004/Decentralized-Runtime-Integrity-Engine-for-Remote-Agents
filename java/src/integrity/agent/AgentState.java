package integrity.agent;

import java.util.*;

/** Dummy remote worker. Only whitelisted state is measured, not full heap. */
public final class AgentState {
    public static Map<String, String> current() {
        Map<String, String> m = new HashMap<>();
        m.put("mode", "AUTO");
        m.put("limit", "100");
        m.put("version", "3");
        return m;
    }
}
