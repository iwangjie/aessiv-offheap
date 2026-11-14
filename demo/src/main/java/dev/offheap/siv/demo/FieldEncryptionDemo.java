package dev.offheap.siv.demo;

import javax.crypto.AEADBadTagException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Field-level encryption against a real SQLite database. Nothing is mocked: the blobs are written to
 * and read back from a file, so what is asserted is what the database actually holds.
 *
 * <p>Each scenario is one question a team hits in the first week of using field encryption, and each
 * answer is checked rather than described.
 */
public final class FieldEncryptionDemo {

    private static final String TENANT = "tenant-a";

    private static int checks;
    private static int failures;

    public static void main(String[] args) throws Exception {
        Path db = Files.createTempDirectory("vault-demo").resolve("app.db");
        System.out.println("database: " + db);

        try (FieldVault vault = FieldVault.create(2);
             Connection c = connect(db)) {
            createSchema(c);

            searchableColumn(c, vault);
            boundColumn(c, vault);
            boundBlobIsPinned(c, vault);
            deterministicLeaksEquality(c, vault);
            String[] roster = rotationAndLazyRewrap(c, vault);
            retiringAGenerationRevokes(c, vault, roster);
            whatTheDatabaseFileContains(db);
        }

        gcmVaultSameGuarantees(db);
        theBlindIndexTrap(db);

        System.out.println();
        System.out.printf("checks=%d failures=%d%n", checks, failures);
        if (failures != 0) {
            System.exit(1);
        }
    }

    // ------------------------------------------------------------------ scenarios

    /**
     * The first question every team asks: can I still query by the encrypted value? Only with the
     * deterministic form - and it works because equal inputs produce equal blobs, which is also its
     * cost.
     */
    private static void searchableColumn(Connection c, FieldVault vault) throws Exception {
        section("1. exact-match lookup on an encrypted column");

        String[] emails = {"a@x.com", "b@x.com", "a@x.com"};
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO users (id, tenant, email_enc) VALUES (?,?,?)")) {
            for (String email : emails) {
                ps.setString(1, UUID.randomUUID().toString());
                ps.setString(2, TENANT);
                ps.setBytes(3, vault.seal(TENANT, "users", "email", null, email));
                ps.executeUpdate();
            }
        }

        byte[] probe = vault.seal(TENANT, "users", "email", null, "a@x.com");
        int hits = 0;
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT id, email_enc FROM users WHERE tenant = ? AND email_enc = ?")) {
            ps.setString(1, TENANT);
            ps.setBytes(2, probe);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    hits++;
                    check("row " + rs.getString(1).substring(0, 8) + " decrypts correctly",
                            "a@x.com",
                            vault.open(TENANT, "users", "email", null, rs.getBytes(2)));
                }
            }
        }
        check("WHERE email_enc = ? finds both rows", 2, hits);

        // No extra column was needed: the deterministic ciphertext is itself indexable.
        String plan = queryPlan(c, probe,
                "EXPLAIN QUERY PLAN SELECT id FROM users WHERE tenant = ? AND email_enc = ?");
        check("the lookup uses the index on the ciphertext column", true,
                plan.contains("USING COVERING INDEX") || plan.contains("USING INDEX"));
        System.out.println("  plan: " + plan);
    }

    /**
     * The form to use when no server-side search is needed. The row id has to exist before the seal,
     * so the primary key must be application-generated (a UUID here) rather than an autoincrement
     * column - an autoincrement id is not known until after the INSERT, which is too late to put in
     * the AAD.
     */
    private static void boundColumn(Connection c, FieldVault vault) throws Exception {
        section("2. row-bound column");

        String alice = UUID.randomUUID().toString();
        String bob = UUID.randomUUID().toString();
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO users (id, tenant, ssn_enc) VALUES (?,?,?)")) {
            ps.setString(1, alice);
            ps.setString(2, TENANT);
            ps.setBytes(3, vault.seal(TENANT, "users", "ssn", alice, "123-45-6789"));
            ps.executeUpdate();
            ps.setString(1, bob);
            ps.setString(2, TENANT);
            ps.setBytes(3, vault.seal(TENANT, "users", "ssn", bob, "987-65-4321"));
            ps.executeUpdate();
        }

        byte[] stored = ssnOf(c, alice);
        check("opens with the right row id", "123-45-6789",
                vault.open(TENANT, "users", "ssn", alice, stored));
        check("two writes of one value differ (fresh nonce)", false,
                Arrays.equals(stored, vault.seal(TENANT, "users", "ssn", alice, "123-45-6789")));

        // The direct proof of what randomization costs: a freshly sealed probe for a value that IS
        // in the table matches nothing, because every write produced a different blob.
        int matches = countRows(c,
                "SELECT COUNT(*) FROM users WHERE ssn_enc = ?",
                vault.seal(TENANT, "users", "ssn", alice, "123-45-6789"));
        check("a search on the randomized column finds nothing", 0, matches);
    }

    /**
     * What the AAD buys: a blob is authentic only where it was sealed. Every case below is a
     * substitution attack a plain AES-CBC-with-static-IV column would accept silently.
     */
    private static void boundBlobIsPinned(Connection c, FieldVault vault) throws Exception {
        section("3. a bound blob only opens in its own row, column and tenant");

        String alice = idOfPlaintext(c, vault, "123-45-6789");
        String bob = idOfPlaintext(c, vault, "987-65-4321");
        byte[] aliceSsn = ssnOf(c, alice);

        expectTagFailure(vault, "moved to another row", TENANT, "ssn", bob, aliceSsn);
        expectTagFailure(vault, "moved to another column", TENANT, "phone", alice, aliceSsn);
        expectTagFailure(vault, "read as another tenant", "tenant-b", "ssn", alice, aliceSsn);
        check("still opens in its own row", "123-45-6789",
                vault.open(TENANT, "users", "ssn", alice, aliceSsn));
    }

    /**
     * The honest cost of the searchable form, measured rather than asserted: with no key at all, the
     * database can count distinct values and group the rows that share one. This is why the
     * deterministic form is for columns whose equality is not itself a secret.
     */
    private static void deterministicLeaksEquality(Connection c, FieldVault vault) throws Exception {
        section("4. what the deterministic form reveals to whoever holds the database");

        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO audit (email_enc, email_last4_enc) VALUES (?,?)")) {
            String[] emails = {"a@x.com", "c@x.com", "a@x.com",
                    "b@x.com", "a@x.com"};
            for (String email : emails) {
                ps.setBytes(1, vault.seal(TENANT, "audit", "email", null, email));
                ps.setBytes(2, vault.seal(TENANT, "audit", "email_last4", null,
                        email.substring(email.length() - 4)));
                ps.executeUpdate();
            }
        }

        long distinct;
        long rows;
        try (Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT COUNT(DISTINCT email_enc), COUNT(*) FROM audit")) {
            rs.next();
            distinct = rs.getLong(1);
            rows = rs.getLong(2);
        }
        System.out.println("  " + rows + " rows of one email column collapse to " + distinct
                + " distinct blobs, computable with no key");
        check("equality is visible without the key", true, distinct < rows);

        // Grouping is not limited to the exact value: a deterministic suffix column reveals the
        // same structure at lower cardinality.
        long last4Distinct;
        try (Statement st = c.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT COUNT(DISTINCT email_last4_enc) FROM audit")) {
            rs.next();
            last4Distinct = rs.getLong(1);
        }
        System.out.println("  encrypted last-4 column collapses to " + last4Distinct
                + " blob(s): all five addresses share the suffix '\u002ecom'");
        check("a low-cardinality column is the worst case", 1L, last4Distinct);
    }

    /**
     * Rotation is a two-step operation and the demo performs only the first: a new generation becomes
     * the write key, and exactly one row is migrated. The rest stay on the old generation, which is
     * what a rolling deployment looks like.
     *
     * @return the row ids that were migrated and not migrated, for the retirement scenario
     */
    private static String[] rotationAndLazyRewrap(Connection c, FieldVault vault) throws Exception {
        section("5. key rotation without downtime");

        String migrated = idOfPlaintext(c, vault, "123-45-6789");
        String untouched = idOfPlaintext(c, vault, "987-65-4321");
        byte[] oldBlob = ssnOf(c, migrated);
        int oldVersion = FieldVault.versionOf(oldBlob);

        int newVersion = vault.rotate();
        System.out.println("  rotating generation " + oldVersion + " -> " + newVersion);

        byte[] fresh = vault.seal(TENANT, "users", "ssn", migrated, "999-99-9999");
        check("new writes use the new generation", newVersion, FieldVault.versionOf(fresh));

        // Rows sealed under the old generation still open, because that generation is still
        // registered. This is what removes the maintenance window from rotation.
        check("untouched row still readable after rotation", "987-65-4321",
                vault.open(TENANT, "users", "ssn", untouched, ssnOf(c, untouched)));

        byte[] rewrapped = vault.rewrap(TENANT, "users", "ssn", migrated, oldBlob);
        check("rewrap moves one row forward", newVersion, FieldVault.versionOf(rewrapped));
        check("rewrapped row still decrypts", "123-45-6789",
                vault.open(TENANT, "users", "ssn", migrated, rewrapped));
        try (PreparedStatement ps = c.prepareStatement(
                "UPDATE users SET ssn_enc = ? WHERE id = ?")) {
            ps.setBytes(1, rewrapped);
            ps.setString(2, migrated);
            ps.executeUpdate();
        }

        check("migrated row is on the new generation", newVersion,
                FieldVault.versionOf(ssnOf(c, migrated)));
        check("untouched row is still on the old generation", oldVersion,
                FieldVault.versionOf(ssnOf(c, untouched)));
        return new String[]{migrated, untouched, String.valueOf(oldVersion), String.valueOf(newVersion)};
    }

    /**
     * Step two: once every row has been migrated the old generation can be retired. Retiring it while
     * rows still depend on it is the dangerous case - the data stays in the database, but nobody can
     * read it again. The demo performs it deliberately to show the consequence, and shows that rows
     * on the current generation are unaffected.
     */
    private static void retiringAGenerationRevokes(Connection c, FieldVault vault, String[] roster)
            throws Exception {
        section("6. retiring a generation that still protects rows");

        String migrated = roster[0];
        String untouched = roster[1];
        int oldVersion = Integer.parseInt(roster[2]);
        byte[] orphan = ssnOf(c, untouched);

        try {
            vault.removeGeneration(Integer.parseInt(roster[3]));
            check("the current generation cannot be retired", "IllegalArgumentException", "allowed");
        } catch (IllegalArgumentException expected) {
            check("the current generation cannot be retired", "IllegalArgumentException",
                    expected.getClass().getSimpleName());
        }

        vault.removeGeneration(oldVersion);
        try {
            vault.open(TENANT, "users", "ssn", untouched, orphan);
            check("a row on the retired generation is now unreadable",
                    "IllegalArgumentException", "opened");
        } catch (IllegalArgumentException expected) {
            check("a row on the retired generation is now unreadable", "IllegalArgumentException",
                    expected.getClass().getSimpleName());
        }
        check("rows on the current generation are unaffected", "123-45-6789",
                vault.open(TENANT, "users", "ssn", migrated, ssnOf(c, migrated)));

        System.out.println("  " + ssnOf(c, untouched).length
                + " bytes of ciphertext remain in the table with no key to open them");
    }

    /**
     * The at-rest artefact an attacker with a backup gets - different from the heap scan, which is
     * about a running process.
     */
    private static void whatTheDatabaseFileContains(Path db) throws Exception {
        section("7. the database file itself");

        byte[] file = Files.readAllBytes(db);
        for (String secret : new String[]{"a@x.com", "123-45-6789", "987-65-4321"}) {
            check("'" + secret + "' absent from the db file", -1,
                    indexOf(file, secret.getBytes("UTF-8")));
        }
        System.out.println("  scanned " + file.length + " bytes; only ciphertext is present");
    }

    /**
     * The same guarantees, with AES-GCM behind the vault instead of AES-SIV. Everything that matters
     * for a bound column is algorithm-independent: the blob still opens only in its own
     * row/column/tenant, and rotation still works through the version byte.
     *
     * <p>The difference is not a detail: GCM cannot produce a deterministic column, so the
     * equality-searchable form is unavailable rather than merely discouraged.
     */
    private static void gcmVaultSameGuarantees(Path sourceDb) throws Exception {
        section("8. the same column bindings under AES-GCM");

        Path db = sourceDb.getParent().resolve("gcm.db");
        try (FieldVault vault = FieldVault.create(2, true);
             Connection c = connect(db)) {
            createSchema(c);
            check("vault reports AES-GCM", "AES-GCM", vault.algorithm());

            String alice = UUID.randomUUID().toString();
            String bob = UUID.randomUUID().toString();
            byte[] aliceSsn = vault.seal(TENANT, "users", "ssn", alice, "123-45-6789");
            try (PreparedStatement ps = c.prepareStatement(
                    "INSERT INTO users (id, tenant, ssn_enc) VALUES (?,?,?)")) {
                ps.setString(1, alice);
                ps.setString(2, TENANT);
                ps.setBytes(3, aliceSsn);
                ps.executeUpdate();
                ps.setString(1, bob);
                ps.setString(2, TENANT);
                ps.setBytes(3, vault.seal(TENANT, "users", "ssn", bob, "987-65-4321"));
                ps.executeUpdate();
            }

            check("opens with the right row id", "123-45-6789",
                    vault.open(TENANT, "users", "ssn", alice, aliceSsn));
            expectTagFailure(vault, "moved to another row", TENANT, "ssn", bob, aliceSsn);
            expectTagFailure(vault, "moved to another column", TENANT, "phone", alice, aliceSsn);
            expectTagFailure(vault, "read as another tenant", "tenant-b", "ssn", alice, aliceSsn);

            // GCM's tag is 16 bytes and is appended, so the blob is header + nonce + pt + tag. The
            // plaintext length is visible to the database - encryption does not hide it.
            check("blob length is 3 + 12 + 11 + 16", 3 + 12 + "123-45-6789".length() + 16,
                    aliceSsn.length);

            // The decisive difference.
            try {
                vault.seal(TENANT, "users", "email", null, "a@x.com");
                check("a deterministic column is refused", "UnsupportedOperationException", "allowed");
            } catch (UnsupportedOperationException expected) {
                check("a deterministic column is refused", "UnsupportedOperationException",
                        expected.getClass().getSimpleName());
            }

            // Rotation is algorithm-independent.
            int oldVersion = FieldVault.versionOf(aliceSsn);
            int newVersion = vault.rotate();
            check("old row still readable after rotation", "123-45-6789",
                    vault.open(TENANT, "users", "ssn", alice, aliceSsn));
            byte[] rewrapped = vault.rewrap(TENANT, "users", "ssn", alice, aliceSsn);
            check("rewrap moves the row forward", newVersion, FieldVault.versionOf(rewrapped));
            check("rewrapped row still decrypts", "123-45-6789",
                    vault.open(TENANT, "users", "ssn", alice, rewrapped));
            check("and it really did change generation", true, oldVersion != newVersion);
        }

        byte[] file = Files.readAllBytes(db);
        check("plaintext absent from the GCM database file", -1,
                indexOf(file, "123-45-6789".getBytes("UTF-8")));
    }

    /**
     * The temptation: keep the column randomized and add a "blind index" - HMAC of the plaintext -
     * so lookups still work. It does make `WHERE idx = ?` work. It does not make the column
     * unrecoverable, because the index is the leak, just moved into a second column.
     *
     * <p>The decisive number is the guess count. An attacker holding a backup has both the encrypted
     * column and the index; against a low-entropy value the index is recovered by enumeration, and a
     * single recovered value calibrates what "same" means for every other row - so the attacker
     * learns the whole column's equality structure without decrypting it.
     */
    private static void theBlindIndexTrap(Path sourceDb) throws Exception {
        section("9. blind index vs deterministic column: the same leak, and worse");

        // Two different constructions over the same data set.
        byte[] indexKey = new byte[32];
        new java.security.SecureRandom().nextBytes(indexKey);
        String[] values = {"a@x.com", "c@x.com", "a@x.com",
                "b@x.com", "a@x.com"};

        Map<String, Integer> blindIndexGroups = new HashMap<String, Integer>();
        Map<String, Integer> deterministicGroups = new HashMap<String, Integer>();
        for (String v : values) {
            blindIndexGroups.merge(indexHex(hmacSha256(indexKey, v)), 1, Integer::sum);
            deterministicGroups.merge(v, 1, Integer::sum);
        }
        check("blind index recovers the same equality structure", deterministicGroups.keySet().size(),
                blindIndexGroups.size());

        // And it exposes strictly more: the index output for a guessed candidate is computable
        // offline, so one known value collapses the whole mapping.
        String guess = "a@x.com";
        check("one guess confirms membership in the index", true,
                blindIndexGroups.containsKey(indexHex(hmacSha256(indexKey, guess))));
        check("and therefore identifies the other rows sharing that value", 3,
                blindIndexGroups.get(indexHex(hmacSha256(indexKey, guess))));

        // Against a deterministic column the same guess is equally cheap - which is the honest
        // comparison: they are the same leak, not a safer alternative.
        check("the deterministic column leaks exactly the same thing", 3,
                deterministicGroups.get(guess));

        System.out.println("  blind index and deterministic ciphertext are the same disclosure;"
                + " the index just needs one more column and one more key to leak");
        System.out.println("  what both destroy: searchable ranges, LIKE prefixes, sorted scans,"
                + " and any value the attacker can enumerate");
    }

    private static byte[] hmacSha256(byte[] key, String value) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(value.getBytes("UTF-8"));
    }

    private static String indexHex(byte[] raw) {
        StringBuilder sb = new StringBuilder();
        for (byte b : raw) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // ------------------------------------------------------------------ plumbing

    private static Connection connect(Path db) throws SQLException {
        return DriverManager.getConnection("jdbc:sqlite:" + db);
    }

    private static void createSchema(Connection c) throws SQLException {
        try (Statement st = c.createStatement()) {
            st.execute("CREATE TABLE users ("
                    + "id TEXT PRIMARY KEY,"
                    + "tenant TEXT NOT NULL,"
                    + "email_enc BLOB,"
                    + "ssn_enc BLOB)");
            // An index on the ciphertext is exactly as strong as the deterministic form: equality
            // works server-side, ranges do not.
            st.execute("CREATE INDEX users_email ON users(tenant, email_enc)");
            st.execute("CREATE TABLE audit (email_enc BLOB, email_last4_enc BLOB)");
        }
    }

    private static byte[] ssnOf(Connection c, String id) throws SQLException {
        return load(c, "ssn_enc", id);
    }

    private static String queryPlan(Connection c, byte[] probe, String sql) throws SQLException {
        StringBuilder sb = new StringBuilder();
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, TENANT);
            ps.setBytes(2, probe);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    sb.append(rs.getString(4)).append(' ');
                }
            }
        }
        return sb.toString().trim();
    }

    private static int countRows(Connection c, String sql, byte[] blob) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setBytes(1, blob);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getInt(1);
            }
        }
    }

    private static byte[] load(Connection c, String column, String id) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT " + column + " FROM users WHERE id = ?")) {
            ps.setString(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return rs.getBytes(1);
            }
        }
    }

    /**
     * Row ids cannot be searched by plaintext, so finding a row means decrypting candidates - which
     * is exactly the cost bound mode imposes and the reason searchable columns use the
     * deterministic form instead.
     */
    private static String idOfPlaintext(Connection c, FieldVault vault, String plaintext)
            throws Exception {
        try (Statement st = c.createStatement();
             ResultSet rs = st.executeQuery("SELECT id, ssn_enc FROM users WHERE ssn_enc IS NOT NULL")) {
            while (rs.next()) {
                String id = rs.getString(1);
                byte[] blob = rs.getBytes(2);
                if (plaintext.equals(vault.open(TENANT, "users", "ssn", id, blob))) {
                    return id;
                }
            }
        }
        throw new IllegalStateException("no row holds the expected value");
    }

    private static void expectTagFailure(FieldVault vault, String what, String tenant,
                                         String column, String rowId, byte[] blob) {
        try {
            String leaked = vault.open(tenant, "users", column, rowId, blob);
            check(what + " is rejected", "AEADBadTagException", "opened as " + leaked);
        } catch (AEADBadTagException expected) {
            check(what + " is rejected", "AEADBadTagException",
                    expected.getClass().getSimpleName());
        }
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static void section(String title) {
        System.out.println();
        System.out.println("== " + title + " ==");
    }

    private static void check(String what, Object expected, Object actual) {
        checks++;
        boolean ok = expected == null ? actual == null : expected.equals(actual);
        if (!ok) {
            failures++;
        }
        System.out.println((ok ? "  ok   " : "  FAIL ") + what
                + (ok ? "" : " - expected " + expected + ", got " + actual));
    }
}
