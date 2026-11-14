# aessiv-offheap

AES-SIV (RFC 5297) and AES-GCM (SP 800-38D) for **JDK 8**, with the key material never entering the
Java heap.

Key bytes, AES round keys, CMAC subkeys and the GCM GHASH subkey live in native memory allocated
through `sun.misc.Unsafe.allocateMemory`, are zeroed before being freed, and have no `byte[]`,
`String`, `SecretKeySpec` or `BigInteger` representation anywhere in the library. A heap dump taken while a key
is live contains no trace of it - verified by scanning a real HPROF dump, not asserted.

Plaintext and ciphertext **do** stay on the heap: they are the caller's data, not the key, and
requiring off-heap I/O for them would make the library unusable.

## Build and run

No build tool: the library is 11 classes and a `javac` invocation. JDK 8 is required (it uses
`sun.misc.Unsafe`), JDK 21+ only for the TLA+ model.

```bash
git clone https://github.com/iwangjie/aessiv-offheap
cd aessiv-offheap

JDK8=/path/to/jdk8
$JDK8/bin/javac -d build/classes src/main/java/dev/offheap/siv/*.java
```

Then run the full verification - RFC vectors, a differential test against pycryptodome, a TLA+
model, a bytecode gate, an HPROF heap scan and a real SQLite field-encryption demo:

```bash
tools/verify-all.sh          # about 40 s; downloads what it needs into build/ and verify/
```

Individual demos, once `tools/verify-all.sh` has populated `build/`:

```bash
CP="build/classes:build/demo:build/demo-lib/*"
$JDK8/bin/java -cp "$CP" dev.offheap.siv.demo.InsertAndPageDemo      # insert one row, page a list
$JDK8/bin/java -cp "$CP" dev.offheap.siv.demo.FieldEncryptionDemo    # 41 security assertions
$JDK8/bin/java -cp "$CP" dev.offheap.siv.demo.PhoneSearchBenchmark 200000   # search cost at scale
```

Requirements: JDK 8, Python 3 with `pycryptodome` (differential test), `sqlite3` (demo),
JDK 21+ (TLA+ model). Everything else is downloaded on demand.

## Status

Written as a reference implementation, not a published library: there is no Maven artifact, no
release, and the API may change. The security properties are backed by the checks in
[Verification](#verification) - including negative controls, so a passing run means something.

## API

```java
try (SivKey key = SivKey.generate()) {                  // 32-byte AES-128-SIV key from /dev/urandom
    byte[][] ad = { header, context };
    byte[] z = key.seal(ad, plaintext);                 // Z = V || C, V is the synthetic IV
    byte[] p = key.open(ad, z);                         // AEADBadTagException on any tampering
}

try (SivKey key = SivKey.fromFile(Paths.get("/run/keys/api"))) {
    byte[] z = key.sealWithNonce(nonce, ad, plaintext);  // RFC 5297 nonce variant
    byte[] p = key.openWithNonce(nonce, ad, z);
}
```

`SivKey` accepts 32, 48 and 64-byte keys (AES-128/192/256 in each half).

`SecretKeyManager` is a named registry over the `Aead` interface, so one manager can hold both
algorithms:

```java
try (SecretKeyManager keys = new SecretKeyManager()) {
    keys.register("searchable", 64);   // AES-256-SIV
    keys.registerGcm("bound");         // AES-256-GCM
    keys.requireDeterministic("searchable");   // wiring-time check, see below
}
```

`requireDeterministic(name)` throws if the named key has no deterministic form. Call it wherever a
column is wired up, not per row: an AES-GCM key in a slot that an equality-searchable column expects
would either fail on every row or, worse, be adapted into output that never repeats - so the column
would silently stop matching itself.

### AES-GCM

```java
try (GcmKey key = GcmKey.generate()) {                   // AES-256-GCM key from /dev/urandom
    byte[] iv = new byte[12];
    SecureRandom.getInstanceStrong().nextBytes(iv);      // 96-bit IV, MUST be unique per key
    byte[] z = key.seal(iv, ad, plaintext);              // C || T
    byte[] p = key.open(iv, ad, z);                       // AEADBadTagException on any tampering
}
```

`GcmKey` accepts 16, 24 and 32-byte keys (AES-128/192/256-GCM) and requires a 96-bit IV - other IV
lengths need GHASH over the IV and are rejected rather than silently handled differently from what
the caller expects.

**GCM and SIV are not interchangeable:**

| | GCM | SIV |
|---|---|---|
| nonce | mandatory, unique per key | optional (deterministic form) |
| nonce reuse | releases $P_1 \oplus P_2$ and permits tag forgery | nothing to reuse in the deterministic form |
| output | `C \|\| T` | `V \|\| C` |
| hardware | JDK uses AES-NI + PCLMULQDQ | no standard fast path |

If you cannot guarantee nonce uniqueness, use SIV's deterministic form. If you need speed and have a
sound nonce source, use GCM - the JDK's own Cipher does GCM 2-3x faster than anything here, but its
key lives on the heap, which is the trade this library exists to avoid.

Key sources that never touch the heap: `SivKey.generate()`, `SivKey.fromFile(path)`,
`OffHeapKey.read(channel, len)`. `SivKey.importKey(byte[])` exists for interoperability and is the
one entry point that starts from a heap array - the JVM gives no way to wipe the caller's copy.

There is no `getKey()`: the key cannot be read back, only used. `SecretKeyManager.register` on an
existing name closes the previous key and retires its native memory.

`SivKey` is immutable - every operation allocates its own native scratch - so one instance can be
shared across threads without synchronization.

## GCM for database fields - and where it stops

`FieldVault.create(n, true)` backs the vault with AES-256-GCM instead of AES-SIV. The scenario in
`demo/` runs the same assertions against it (scenario 8), and every guarantee a *bound* column needs
is algorithm-independent:

| guarantee | AES-SIV | AES-GCM |
|---|---|---|
| blob only opens in its row/column/tenant | yes | yes |
| fresh value on every write | yes (nonce variant) | yes (96-bit IV) |
| rotation via the version byte | yes | yes |
| plaintext absent from the database file | yes | yes |
| **equality-searchable column** | **yes** (deterministic) | **no** - refused at the call |
| nonce/IV stored with the blob | 16 B (SIV accepts any length) | 12 B, exactly |
| overhead over the plaintext | 3 + 16 + 16 = 35 B | 3 + 12 + 16 = 31 B |

The `equality-searchable` row is the whole decision. GCM has no deterministic form: every write must
use a fresh IV, so two rows holding the same value produce unrelated ciphertexts and
`WHERE col = ?` can never match.
The vault makes that an `UnsupportedOperationException` at the sealing call rather than letting a team
discover it after shipping:

```
== 8. the same column bindings under AES-GCM ==
  ok   moved to another row is rejected
  ok   a deterministic column is refused
  ok   old row still readable after rotation
```

So: **use GCM for columns you never search** (SSN, phone, balance, free text) and SIV where you need
equality. There is no configuration in which GCM backs a searchable column, and no plan to add one -
GCM's security proof requires IV uniqueness, and a deterministic IV derived from the plaintext is
exactly the reuse that breaks it.

### If the column must be searched after all

A bound column cannot be searched, so a team that picked it up front has three options. All three
are measured by `demo/PhoneSearchBenchmark` over 20k and 200k rows:

| approach | 20k rows | 200k rows | hits | what it leaks |
|---|---|---|---|---|
| scan: decrypt every row | 130 ms | 1230 ms | 40 / 400 | nothing |
| deterministic column, indexed | 0.05 ms | 0.17 ms | 20 / 200 | equality |
| dual: token index + bound value | 0.28 ms | 1.84 ms | 20 / 200 | equality |

Scanning is linear: 10x the rows is 9.5x the time. An indexed lookup stays sub-millisecond at both
sizes. So "search a bound column in memory" is a real option, and it is ~2,400x slower at 20k rows
and ~7,300x slower at 200k - the ratio grows with the table, which is why it is not a viable default
for a table that will grow.

The dual-column variant exists because a **deterministic lookup token carries no row identity**. If
someone with write access copies one row's token onto another - or a migration does it by accident -
the index returns rows that do not actually hold that value. Only decrypting the bound column can
detect it:

```
copied row 89135c3c's phone token onto row 7693b318
index says 2 rows match, the bound column confirms 1
```

That one extra decryption per hit is what turns "the index said so" into "the row really holds this
value". The token can also be rotated or dropped independently, so search can be switched off later
without re-encrypting the data.

The choice is not really "SIV or GCM", though - it is **deterministic or randomized**, and the
deterministic option needs no extra column. The ciphertext itself is indexable:

```
plan: SEARCH users USING INDEX users_email (tenant=? AND email_enc=?)
```

No blind-index column, no hash column, no so-called "searchable encryption". The cost is the one
measured in scenario 4: equality is visible to anyone holding the database.

Avoiding that cost is what tempts people into a **blind index** (an HMAC of the plaintext in a second
column) while keeping the data column randomized. Scenario 9 measures what that buys: nothing. The
index reproduces the same equality structure - five rows over three distinct values collapse to
three index values too - and it is *more* exposed, because the index output for a guessed candidate
is computable offline against a stolen backup. One recovered value calibrates "same" for every other
row without any decryption. A blind index is the deterministic leak moved into a second column with
a second key to protect.

Both destroy the same things: ranges, `LIKE` prefixes, sorted scans, and any value an attacker can
enumerate. Neither is a way to keep the leak and have the query.

Cost of choosing GCM here: its IV must be persisted and is 12 bytes, its tag is fixed at 16, and this
implementation is *slower* than SIV (15 vs 20 MB/s) because GHASH is a bit loop. If you need
throughput, the JCE's AES-NI GCM is far faster - at the price of the key living on the heap.

## Encrypting database columns

`demo/` contains a runnable answer to the question this library is usually asked for, and
`tools/demo-field-encryption.sh` runs it against real SQLite files (35 assertions). The
interesting decisions are all at the field level, not the algorithm level:

```java
try (FieldVault vault = FieldVault.create(2)) {           // key ring with two generations
    // Deterministic: equal values -> equal blobs, so hashing and indexing work server-side.
    byte[] emailBlob = vault.seal("tenant-a", "users", "email", null, email);
    // Bound: fresh nonce, and the blob only opens in this row/column/tenant.
    byte[] ssnBlob = vault.seal("tenant-a", "users", "ssn", userId, ssn);
}
```

Stored format: `[format][keyVersion][mode][nonce?][ciphertext]`. A nonce is not secret, only unique,
and it is *not* part of the SIV output - it is an extra S2V component - so the caller has to store it
next to the blob. The mode byte is checked against the call site, so a bound blob cannot be opened
through the deterministic path (which would skip the row-id check).

Three decisions are worth copying:

**1. Bind the blob, or it is a substitution oracle.** Every AAD component is a separate S2V
component - tenant, table, column, and row id - so a blob sealed for `users.ssn` row *A* fails to open
as row *B*, as `users.phone`, or under another tenant. A `tenant`/`column` AAD alone would let a
privileged reader move ciphertext between rows, which for a `balance` or `role` column is a
correctness bug the application cannot detect (scenario 3).

**2. Row binding requires application-generated primary keys.** The row id must exist before the
seal, so an `AUTOINCREMENT` key is unusable - you learn it after the INSERT. Use a UUID or a
sequence allocated up front. This is the most common early blocker.

**3. Pick per column, and know what each choice gives up.**

| | deterministic (no row id) | bound (row id in AAD) |
|---|---|---|
| `WHERE col = ?` | works, index-supported (verified: `USING INDEX`) | matches nothing - every write differs |
| `ORDER BY`, ranges, `LIKE` | meaningless - ciphertext order | meaningless |
| equal values visible to the DBA | yes | no |
| blob relocatable | yes | no |
| suitable for | e-mail, external id, tenant key | SSN, phone, balance, anything sensitive |

The deterministic form's leak is equality, measured in scenario 4: five rows of one address column
collapse to three distinct blobs, and an encrypted `last4` column collapses to **one** - the database
learns the shape of the data without any key. Never use it for low-cardinality columns.

A GCM vault refuses the deterministic form and accepts the bound one; see
[GCM for database fields](#gcm-for-database-fields---and-where-it-stops) above.

**Rotation** is `[keyVersion]` plus a key ring: `vault.rotate()` makes new writes use the new
generation while old rows keep opening, and `rewrap` migrates one row at a time (on read, or in a
background sweep). `removeGeneration` retires a key and thereby makes its rows permanently
unreadable - which is the intended revocation semantics and also the way to lose data, as scenario 6
shows: 46 bytes of ciphertext left in the table with no key to open them.

**What the database still sees**, regardless of the above: row counts, timestamps, indexes, sizes
(the blob length reveals the plaintext length to within a block), and access patterns. Field
encryption is not equivalent to encrypting the volume; it defends against backups, replicas, log
scrapes and DBA curiosity, not against a compromised application process.

## Design

| Concern | Where it lives |
|---|---|
| raw key | `NativeBuffer`, zeroed after the key schedules exist |
| AES round keys | `NativeBuffer` (`16 * (Nr+1)` bytes per half) |
| CMAC subkeys K1/K2 | `NativeBuffer`, derived once per key, shared by all S2V calls |
| CMAC chain / pending block | `NativeBuffer`, per-operation scratch, zeroed on close |
| GCM GHASH subkey H | `NativeBuffer`, derived once per key (`E(K, 0^128)`) |
| GCM GHASH state | `NativeBuffer`, per-operation scratch, zeroed on close |
| AES state | four `int` locals - derived from the message being encrypted, not the key alone |
| plaintext / ciphertext | caller's heap arrays |

The key is split per RFC 5297 §2.6: the left half drives S2V (CMAC), the right half drives CTR. The
two halves are expanded into their own schedules and the raw key region is zeroed before the
constructor returns, so after construction the only representation of the key in the process is the
expanded schedule.

SIV is deterministic: identical AD sets and plaintexts produce identical outputs. Use
`sealWithNonce` when that matters.

### Performance

Measured on JDK 8 (`tools/verify-all.sh` does not assert these; they exist to bound expectations):

| case | SIV | GCM |
|---|---|---|
| seal 64 B | 4.7 µs/op | 4.3 µs/op |
| seal 64 KiB | 20 MB/s | 15 MB/s |
| AES block (this library) | 267 ns / 16 B | - |
| AES block (JCE, AES-NI) | 9.4 ns / 16 B | - |

GCM is slower than SIV here despite doing less work: GHASH is a 128-iteration bit loop per block,
while SIV's CTR mode is plain AES. Both are roughly 30x slower than AES-NI, which is the price of a
portable byte-oriented S-box with the key schedule in native memory. If throughput matters more than the heap guarantee, use a native AES
implementation behind a `MemorySegment`-based binding rather than making this one faster.

### AES implementation

Byte-oriented S-box with arithmetic MixColumns (no T-tables). Constant-time bitsliced AES is out of
scope; the only data-dependent memory access is a 256-byte table lookup on the *state*, which is the
standard software tradeoff. If your threat model includes an attacker with cache-timing access to
the same core, this implementation is not sufficient.

Runs unchanged on JDK 8, 22 and 25 with the same `build/classes` - no `--add-opens`, no
`--sun-misc-unsafe-memory-access` flag. `sun.misc.Unsafe.allocateMemory` is deprecated for removal
in future JDKs, so a long-lived deployment should pin the JDK or plan for `java.lang.foreign`
(`MemorySegment`) once the floor moves past 21.

## Verification

```
tools/verify-all.sh
```

Nine independent checks, each of which can fail:

1. **RFC 5297 A.1/A.2 vectors** - deterministic and nonce-based, byte-exact.
2. **Differential test** vs pycryptodome: 406 cases, `AES.MODE_SIV` (202: key lengths 32/48/64,
   AD counts 0-3, AD component lengths 0-63, plaintexts 0-129 bytes, with and without nonces) and
   `AES.MODE_GCM` (204: key lengths 16/24/32, same AD/plaintext grid).
3. **NIST/McGrew-Viega GCM vectors** - AES-256 test cases 13-16, including the empty-input case and
   the 20-byte-AAD case.
4. **TLA+ model** (`verify/OffHeapKey.tla`) - enumerates every reachable state of a transition system
   that models key generation, key expansion, CMAC subkey derivation, the GHASH subkey, native reads
   and destruction, and asserts `[]NoKeyInHeap`. Exhaustive, not sampled: 78,699,372 states
   generated, 4,830,383 distinct.
5. **Negative control for the model** - the same spec with `AllowLeak=TRUE` (a key handed to
   `SecretKeySpec`) must report `Invariant NoKeyInHeap is violated`. A model that cannot express the
   bug proves nothing.
6. **Bytecode gate** (`tools/check-bytecode.sh`) - no field of type `byte[]`/`char[]`/`String`/
   `BigInteger`/`SecretKeySpec` (except the public FIPS-197 S-box and the `/dev/urandom` path
   constant), no reference to `SecretKeySpec` or `javax.crypto.Cipher`, and `Unsafe.allocateMemory`/
   `freeMemory` confined to one class.
7. **Native-memory accounting** - `NativeBuffer` counts live regions, and 5000 keys opened and
   closed leave the count at its starting value. A deliberate unclosed region is asserted to move the
   count, so the zero is not just a counter that never fires.
8. **Heap-dump scan** (`tools/heap-scan.sh`) - a live `SivKey` and a live `GcmKey` are dumped with
   `jmap`, and the raw dump is searched for the full key, each half, 8-byte fragments, and the
   key-derived CMAC subkeys `K1`/`K2` and GHASH subkey `H`: 0 hits. The same pipeline against a
   deliberate `byte[]` leak (`LeakyControl`) finds 12, which is what makes the 0 meaningful.
9. **Field encryption against a database** (`tools/demo-field-encryption.sh`) - 41 assertions over
   two real SQLite files: deterministic search with a verified index plan, row/column/tenant binding
   rejecting substitution, equality leakage measured, blind-index equivalence measured, rotation with
   lazy rewrap, key retirement, the plaintext absent from the file, and the same bindings repeated
   with AES-GCM behind the vault.

## Limits - what this does not prove

* **No proof about the JVM.** `Unsafe.allocateMemory` returns memory the JVM never inspects, so the GC
  cannot copy it and a heap dump cannot contain it. But a JIT compiler may spill AES state to a
  thread stack, the kernel may swap the native page, and a core dump of the process contains
  everything. Off-heap is not "nowhere".
* **Timing.** Not constant-time against a cache-timing attacker (see above). `equalsConstantTime` is
  used for both tag comparisons.
* **GHASH is not constant-time either.** The 128-iteration bit loop branches on the bits of the MAC
  state. A PCLMULQDQ implementation (or a table-free constant-time carryless multiply) is the fix,
  and is not done here.
* **GCM's nonce obligation is on the caller.** The library rejects a wrong IV length and nothing
  else; it cannot detect a nonce reused with the same key, because doing so would require retaining
  every nonce - which is state this design deliberately does not keep.
* **The caller's boundary.** `importKey(byte[])` and every plaintext/ciphertext array are the
  caller's problem. So is anything the caller does with the returned `byte[]`.
* **The key schedule is not the key, but it is worth as much.** An attacker who can read the AES round
  keys recovers the encryption function. Off-heap only removes the *heap dump / GC copies / byte[]
  scan* class of exposure; it does not defend against code execution in the same process.
