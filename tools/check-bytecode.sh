#!/usr/bin/env bash
# Static gate over the compiled library: no class may hold key material in a heap object.
#
# Checked on declarations, not on string constants used for exception messages:
#
#   1. No field of a heap-carrier type - byte[], char[], int[], long[], String, BigInteger,
#      SecretKeySpec. A field is the only thing that can outlive a call, so it is the only real
#      "key lives in the heap" risk that is not the caller's own array. Two fields are allowlisted
#      because they hold no key material at all:
#        byte[] SBOX      public FIPS-197 substitution table
#        String URANDOM   the filesystem path "/dev/urandom"
#   2. No reference to SecretKeySpec or javax.crypto.Cipher anywhere: those are the two standard
#      ways key bytes get copied into immutable heap objects (and out of our control).
#   3. Unsafe.allocateMemory / freeMemory must be referenced from NativeBuffer only, so every native
#      allocation in the library is auditable in one file.
#
# Exit status is the verdict; nothing is printed when the gate passes except the class count.
set -uo pipefail

classpath=${1:-build/classes}
javap_bin=${JAVAP:-javap}
fail=0

report() {
    printf 'FAIL %s\n' "$*"
    fail=1
}

classes=$(cd "$classpath" && find . -name '*.class' | sed 's|^\./||; s|\.class$||; s|/|.|g' | sort)
signatures=$("$javap_bin" -p -cp "$classpath" $classes)
bodies=$("$javap_bin" -p -c -cp "$classpath" $classes)

# 1. Field declarations whose type can alias key material on the heap.
field_hits=$(printf '%s\n' "$signatures" |
    grep -E '^\s+.*(byte\[\]|char\[\]|int\[\]|long\[\]|java\.lang\.String|BigInteger|SecretKeySpec)\s+\w+\s*;' |
    grep -vE '\bSBOX;|\bURANDOM;' || true)
if [ -n "$field_hits" ]; then
    report "heap-carrier field declared:"
    printf '%s\n' "$field_hits"
fi

# 2. Standard JCE key carriers.
for forbidden in 'javax/crypto/spec/SecretKeySpec' 'javax/crypto/Cipher'; do
    hits=$(printf '%s\n' "$bodies" | grep -F "$forbidden" || true)
    if [ -n "$hits" ]; then
        report "forbidden type in bytecode: $forbidden"
        printf '%s\n' "$hits" | head -5
    fi
done

# 3. Native allocation confined to NativeBuffer.
for method in allocateMemory freeMemory; do
    owners=$(printf '%s\n' "$bodies" |
        grep -B200 "Method sun/misc/Unsafe.$method" |
        grep -oE '^[a-z][A-Za-z0-9_.]*\.[A-Z][A-Za-z0-9_]*' | sort -u |
        sed 's/.*\.//' || true)
    extra=$(printf '%s\n' "$owners" | grep -vx 'NativeBuffer' | grep -v '^$' || true)
    if [ -n "$extra" ]; then
        report "$method referenced outside NativeBuffer: $(echo $extra)"
    fi
done

if [ "$fail" -eq 0 ]; then
    echo "bytecode gate: 0 findings across $(printf '%s\n' "$classes" | wc -l) classes"
fi
exit "$fail"
