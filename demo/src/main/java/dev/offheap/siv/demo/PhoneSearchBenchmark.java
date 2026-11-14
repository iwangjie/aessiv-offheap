package dev.offheap.siv.demo;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;

/**
 * Three ways to look a phone number up, measured on the same 20,000 rows.
 *
 * <p>The question this answers is "if I must search the bound column, do I have to decrypt the whole
 * table?" The answer is no, but the alternatives are not free, and the cost of the naive one is what
 * makes that clear.
 *
 * <ol>
 *   <li><b>scan</b> - bound column only: read every row, decrypt, compare in memory. Correct, and
 *       O(N) decryptions per lookup.
 *   <li><b>deterministic</b> - seal the phone with no row id, so equal values give equal bytes and
 *       the database can index it. One index probe, no full decryption.
 *   <li><b>dual</b> - bound column for the authoritative value plus a separate deterministic lookup
 *       token. Searching uses the token; the value still comes from the bound column, so the token
 *       cannot be abused to read another row's data.
 * </ol>
 *
 * <p>Option 2 and 3 leak the same thing to whoever holds the database (which rows share a phone
 * number), so 3 only earns its extra column when the token has to be rebuildable or rotated
 * independently of the data - which is exactly the case for a value you might want to stop
 * searching later.
 */
public final class PhoneSearchBenchmark {

    private static final String TENANT = "tenant-a";
    private static int ROWS = 20000;
    /** Every 500th row shares this number with the one before it, so a lookup finds several hits. */
    private static final String TARGET = "{{PHONE_2b758266}}";

    public static void main(String[] args) throws Exception {
        if (args.length > 0) {
            ROWS = Integer.parseInt(args[0]);
        }
        Path db = Files.createTempDirectory("phone-bench").resolve("app.db");
        System.out.println("db: " + db);
        System.out.println("rows: " + ROWS);

        try (FieldVault vault = FieldVault.create(1, false);
             Connection c = DriverManager.getConnection("jdbc:sqlite:" + db)) {

            createSchema(c);
            loadRows(c, vault);

            // One warm-up pass so the JIT has compiled each path before anything is timed.
            scan(vault, c);
            deterministic(vault, c);
            dual(vault, c);

            int rounds = 5;
            long scan = median(rounds, () -> scan(vault, c));
            long det = median(rounds, () -> deterministic(vault, c));
            long dual = median(rounds, () -> dual(vault, c));

            System.out.println();
            System.out.printf("%-40s %8s %14s%n", "approach", "hits", "ms/lookup");
            System.out.printf("%-40s %8d %14.2f%n", "scan: decrypt every row", hits("scan", vault, c),
                    scan / 1000.0);
            System.out.printf("%-40s %8d %14.2f%n", "deterministic column, indexed",
                    hits("det", vault, c), det / 1000.0);
            System.out.printf("%-40s %8d %14.2f%n", "dual: token index + bound value",
                    hits("dual", vault, c), dual / 1000.0);
            System.out.printf("%nscan is %.0fx the indexed lookup (median of %d runs)%n",
                    (double) scan / det, rounds);

            System.out.println();
            System.out.println("what makes the dual approach necessary rather than redundant:");
            staleTokenIsCaught(vault, c);
        }
    }

    // ------------------------------------------------------------------ the three approaches

    /**
     * Option 1: no index is possible, so every row must be fetched and decrypted. This is the
     * baseline the question is really about - it is not wrong, it is just linear in table size.
     */
    private static long scan(FieldVault vault, Connection c) throws Exception {
        long start = System.nanoTime();
        int hits = 0;
        try (Statement st = c.createStatement();
             ResultSet rs = st.executeQuery("SELECT id, phone_enc FROM users")) {
            while (rs.next()) {
                String id = rs.getString(1);
                if (TARGET.equals(vault.open(TENANT, "users", "phone", id, rs.getBytes(2)))) {
                    hits++;
                }
            }
        }
        if (hits == 0) {
            throw new IllegalStateException("scan found nothing; the benchmark would be meaningless");
        }
        return (System.nanoTime() - start) / 1000;
    }

    /** Option 2: no row id in the AAD, so the blob is a searchable deterministic value. */
    private static long deterministic(FieldVault vault, Connection c) throws Exception {
        byte[] probe = vault.seal(TENANT, "users", "phone_det", null, TARGET);
        long start = System.nanoTime();
        int hits = 0;
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT id FROM users WHERE tenant = ? AND phone_det = ?")) {
            ps.setString(1, TENANT);
            ps.setBytes(2, probe);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    hits++;
                }
            }
        }
        if (hits == 0) {
            throw new IllegalStateException("deterministic lookup found nothing");
        }
        return (System.nanoTime() - start) / 1000;
    }

    /**
     * Option 3: search the token, read the authoritative value from the bound column. Two index
     * probes plus one decryption per hit - the decryption is what proves the row really holds that
     * number, so a token that was copied to another row cannot return foreign data.
     */
    private static long dual(FieldVault vault, Connection c) throws Exception {
        byte[] probe = vault.seal(TENANT, "users", "phone_tok", null, TARGET);
        long start = System.nanoTime();
        int verified = 0;
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT id, phone_enc FROM users WHERE tenant = ? AND phone_tok = ?")) {
            ps.setString(1, TENANT);
            ps.setBytes(2, probe);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    String id = rs.getString(1);
                    if (TARGET.equals(vault.open(TENANT, "users", "phone", id, rs.getBytes(2)))) {
                        verified++;
                    }
                }
            }
        }
        if (verified == 0) {
            throw new IllegalStateException("dual lookup verified nothing");
        }
        return (System.nanoTime() - start) / 1000;
    }

    /**
     * A token that points at the wrong rows - an attacker who can write to the table, or a migration
     * bug that copied one. The token alone cannot detect this, because it carries no row identity.
     * The bound column does: decrypting it and comparing is what turns "the index said so" into
     * "the row really holds this value".
     */
    private static void staleTokenIsCaught(FieldVault vault, Connection c) throws Exception {
        String victim = firstIdWith(vault, c, TARGET);
        String source = phone(1);
        String other = firstIdWith(vault, c, source);
        byte[] otherToken = tokenOf(c, other);

        try (PreparedStatement ps = c.prepareStatement(
                "UPDATE users SET phone_tok = ? WHERE id = ?")) {
            ps.setBytes(1, otherToken);
            ps.setString(2, victim);
            ps.executeUpdate();
        }
        System.out.println("  copied row " + other.substring(0, 8) + "'s phone token onto row "
                + victim.substring(0, 8));

        // Query for the value the copied token claims, which is the source row's phone number.
        byte[] probe = vault.seal(TENANT, "users", "phone_tok", null, source);
        int believed = 0;
        int verified = 0;
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT id, phone_enc FROM users WHERE tenant = ? AND phone_tok = ?")) {
            ps.setString(1, TENANT);
            ps.setBytes(2, probe);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    believed++;
                    String id = rs.getString(1);
                    if (source.equals(vault.open(TENANT, "users", "phone", id, rs.getBytes(2)))) {
                        verified++;
                    }
                }
            }
        }
        System.out.printf("  index says %d rows match, the bound column confirms %d%n",
                believed, verified);
        if (believed == verified) {
            throw new IllegalStateException(
                    "a stale token was not detected; the verification step is not working");
        }
    }

    private static byte[] tokenOf(Connection c, String id) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT phone_tok FROM users WHERE id = ?")) {
            ps.setString(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getBytes(1);
            }
        }
    }

    private static String firstIdWith(FieldVault vault, Connection c, String phone)
            throws Exception {
        try (Statement st = c.createStatement();
             ResultSet rs = st.executeQuery("SELECT id, phone_enc FROM users")) {
            while (rs.next()) {
                String id = rs.getString(1);
                if (phone.equals(vault.open(TENANT, "users", "phone", id, rs.getBytes(2)))) {
                    return id;
                }
            }
        }
        throw new IllegalStateException("no row holds " + phone);
    }

    private static int hits(String which, FieldVault vault, Connection c) throws Exception {
        if (which.equals("scan")) {
            int n = 0;
            try (Statement st = c.createStatement();
                 ResultSet rs = st.executeQuery("SELECT id, phone_enc FROM users")) {
                while (rs.next()) {
                    if (TARGET.equals(vault.open(TENANT, "users", "phone", rs.getString(1),
                            rs.getBytes(2)))) {
                        n++;
                    }
                }
            }
            return n;
        }
        String column = which.equals("det") ? "phone_det" : "phone_tok";
        byte[] probe = vault.seal(TENANT, "users", column, null, TARGET);
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT COUNT(*) FROM users WHERE tenant = ? AND " + column + " = ?")) {
            ps.setString(1, TENANT);
            ps.setBytes(2, probe);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }

    private interface Timed {
        long run() throws Exception;
    }

    private static long median(int rounds, Timed timed) throws Exception {
        long[] samples = new long[rounds];
        for (int i = 0; i < rounds; i++) {
            samples[i] = timed.run();
        }
        java.util.Arrays.sort(samples);
        return samples[rounds / 2];
    }

    // ------------------------------------------------------------------ data

    private static void createSchema(Connection c) throws SQLException {
        try (Statement st = c.createStatement()) {
            st.execute("CREATE TABLE users ("
                    + "  id        TEXT PRIMARY KEY,"
                    + "  tenant    TEXT NOT NULL,"
                    + "  phone_enc BLOB NOT NULL,"   // bound: the authoritative value
                    + "  phone_det BLOB,"             // deterministic: option 2
                    + "  phone_tok BLOB"              // deterministic token: option 3
                    + ")");
            // Restricted to option 2's rows so each approach is measured against its own data.
            st.execute("CREATE INDEX users_det ON users(tenant, phone_det)");
            st.execute("CREATE INDEX users_tok ON users(tenant, phone_tok)");
        }
    }

    private static void loadRows(Connection c, FieldVault vault) throws Exception {
        long start = System.nanoTime();
        c.setAutoCommit(false);
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO users (id, tenant, phone_enc, phone_det, phone_tok)"
                        + " VALUES (?,?,?,?,?)")) {
            for (int i = 0; i < ROWS; i++) {
                String id = UUID.randomUUID().toString();
                String phone = (i % 500 == 0) ? TARGET : phone(i);
                boolean searchable = i < ROWS / 2;

                ps.setString(1, id);
                ps.setString(2, TENANT);
                ps.setBytes(3, vault.seal(TENANT, "users", "phone", id, phone));
                // Only the first half carries the deterministic forms, so both are measurable.
                ps.setBytes(4, searchable
                        ? vault.seal(TENANT, "users", "phone_det", null, phone) : null);
                ps.setBytes(5, searchable
                        ? vault.seal(TENANT, "users", "phone_tok", null, phone) : null);
                ps.addBatch();
                if (i % 2000 == 1999) {
                    ps.executeBatch();
                }
            }
            ps.executeBatch();
        }
        c.setAutoCommit(true);
        System.out.printf("loaded %d rows in %.1f ms (2-3 sealed columns each)%n",
                ROWS, (System.nanoTime() - start) / 1e6);
    }

    private static String phone(int i) {
        return String.format("138%08d", i);
    }
}
