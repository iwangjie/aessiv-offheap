---------------------------- MODULE OffHeapKey ----------------------------
\* Machine-checked model of the invariant the library relies on: key-derived bytes exist
\* only in native memory, never in a Java heap object.
\*
\* TLC enumerates every reachable state of the transition system below. With AllowLeak=FALSE
\* the invariant NoKeyInHeap must hold in all reachable states - that is the proof obligation.
\* With AllowLeak=TRUE the model can express the bug (a key handed to SecretKeySpec/Cipher/
\* String), so the same checker must report a violation. A model that cannot fail proves
\* nothing; the pair of runs is the evidence.
EXTENDS Naturals, TLC

CONSTANTS KeyBytes, KeyBytesExt, MaxOps, AllowLeak

\* Four native regions and one heap region, each KeyBytesExt bytes wide. Small enough for
\* exhaustive exploration, large enough that "some byte survived" is a real choice.
Addresses == (1..5) \X (1..KeyBytesExt)

VARIABLES
    nativeKey,  \* addresses in native memory currently holding key-derived bytes
    heapKey,    \* addresses inside heap objects currently holding key-derived bytes
    leaked,     \* a byte[] copy has escaped: the JVM cannot wipe it, and the GC may copy it
    ops

vars == <<nativeKey, heapKey, leaked, ops>>

TypeOK ==
    /\ nativeKey \subseteq Addresses
    /\ heapKey   \subseteq Addresses
    /\ leaked    \in BOOLEAN
    /\ ops       \in 0..MaxOps

\* Region 1 = raw key, 2 = AES round keys, 3 = CMAC subkeys K1/K2, 4 = the GCM GHASH subkey H.
\* Region 5 is where a leak would put a copy; it is deliberately outside NativeRegion.
NativeRegion == 1..4

NoKeyInHeap == heapKey = {} /\ leaked = FALSE

\* The temporal form of the same claim: it holds in every state of every behavior, which is what
\* "the key is never in the heap" actually means (a state invariant alone would allow a transient).
KeyNeverInHeap == []NoKeyInHeap

\* Key-derived bytes are never born on the heap: there is no action that adds to heapKey
\* except LeakToHeap.
NoHeapOrigin == heapKey = {} \/ nativeKey # {}

Init ==
    /\ nativeKey = {}
    /\ heapKey = {}
    /\ leaked = FALSE
    /\ ops = 0

\* /dev/urandom -> direct ByteBuffer -> malloc'd region. Nothing touches a byte[].
GenerateKey ==
    /\ ops < MaxOps
    /\ nativeKey = {}
    /\ nativeKey' = {1} \X (1..KeyBytes)
    /\ UNCHANGED <<heapKey, leaked>>
    /\ ops' = ops + 1

\* AES key expansion: the schedule is written to its own native region.
ExpandKey ==
    /\ ops < MaxOps
    /\ nativeKey # {}
    /\ nativeKey' = nativeKey \union ({2} \X (1..KeyBytes))
    /\ UNCHANGED <<heapKey, leaked>>
    /\ ops' = ops + 1

\* RFC 4493 subkeys K1/K2, also native.
DeriveSubkeys ==
    /\ ops < MaxOps
    /\ nativeKey # {}
    /\ nativeKey' = nativeKey \union ({3} \X (1..KeyBytes))
    /\ UNCHANGED <<heapKey, leaked>>
    /\ ops' = ops + 1

\* GCM's GHASH subkey H = E(K, 0^128). Same obligation as the CMAC subkeys: it is key-derived, so
\* a heap copy of H lets an attacker forge tags with no further access.
DeriveGhashSubkey ==
    /\ ops < MaxOps
    /\ nativeKey # {}
    /\ nativeKey' = nativeKey \union ({4} \X (1..KeyBytes))
    /\ UNCHANGED <<heapKey, leaked>>
    /\ ops' = ops + 1

\* A reader may bring any native byte into native scratch. Native-to-native only.
ReadNative ==
    /\ ops < MaxOps
    /\ nativeKey # {}
    /\ \E region \in NativeRegion, offset \in 1..KeyBytes :
         /\ nativeKey' = nativeKey \union {<<region, offset>>}
         /\ UNCHANGED <<heapKey, leaked>>
    /\ ops' = ops + 1

\* destroy(): overwrite with zeros, then free. The bytes are gone from both memories.
Destroy ==
    /\ ops < MaxOps
    /\ nativeKey' = {}
    /\ heapKey' = {}
    /\ UNCHANGED leaked
    /\ ops' = ops + 1

\* The forbidden transition: key bytes enter a heap object. Enabled only under AllowLeak.
LeakToHeap ==
    /\ AllowLeak
    /\ ops < MaxOps
    /\ nativeKey # {}
    /\ \E region \in NativeRegion, offset \in 1..KeyBytes :
         /\ heapKey' = heapKey \union {<<5, offset>>}
         /\ leaked' = TRUE
         /\ UNCHANGED nativeKey
    /\ ops' = ops + 1

\* Stuttering once the operation budget is spent: the transition system is finite only because
\* MaxOps bounds it, and TLC reports a state with no successor as a deadlock, not a proof.
Done ==
    /\ ops = MaxOps
    /\ UNCHANGED vars

Next ==
    \/ Done
    \/ GenerateKey
    \/ ExpandKey
    \/ DeriveSubkeys
    \/ ReadNative
    \/ Destroy
    \/ LeakToHeap

Spec == Init /\ [][Next]_vars /\ WF_vars(Next)

=============================================================================
