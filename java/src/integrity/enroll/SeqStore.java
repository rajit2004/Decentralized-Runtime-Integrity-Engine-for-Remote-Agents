package integrity.enroll;

import java.nio.file.*;

/**
 * Item 14: seq lives on disk, not RAM. Restart resumes instead of REPLAY-flagging self.
 * File: config/seq.dat, single long, fsync on write.
 */
public final class SeqStore {
    private final Path p;

    public SeqStore(Path p) { this.p = p; }

    public long load() {
        try {
            String s = Files.readString(p).trim();
            return Long.parseLong(s);
        } catch (Exception e) { return 1; } // genesis seq 0 enrolled; first live = 1
    }

    public void save(long seq) {
        try {
            Files.createDirectories(p.getParent());
            Files.writeString(p, Long.toString(seq),
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.SYNC);
        } catch (Exception ignored) {}
    }
}
