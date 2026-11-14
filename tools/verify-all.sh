#!/usr/bin/env bash
# Full verification pipeline: JDK 8 build, RFC vectors, pycryptodome differential test, TLA+ model,
# bytecode gate, heap-dump scan. Every step fails the run loudly.
set -euo pipefail
cd "$(dirname "$0")/.."

jdk8=${JDK8:-/usr/lib/jvm/java-8-openjdk}
jdkmod=${JAVAMOD:-/usr/lib/jvm/java-22-openjdk}
javac=$jdk8/bin/javac
javap=$jdk8/bin/javap

echo "== build (JDK 8: $("$jdk8/bin/java" -version 2>&1 | head -1)) =="
rm -rf build/classes build/test-classes build/demo-classes
mkdir -p build/classes build/test-classes build/tmp
# javac on JDK 8 warns that sun.misc.Unsafe is proprietary; that is the point of the library, and
# the only other output we want to see is an error.
"$javac" -d build/classes src/main/java/dev/offheap/siv/*.java 2>&1 |
    grep -F ': error:' || true
"$javac" -cp build/classes -d build/test-classes src/test/java/dev/offheap/siv/*.java 2>&1 |
    grep -F ': error:' || true
ls build/classes/dev/offheap/siv/*.class | wc -l | xargs echo "compiled classes:"

echo
echo "== RFC 5297 / NIST GCM vectors + behavioural self test =="
"$jdk8/bin/java" -cp build/classes:build/test-classes dev.offheap.siv.SivSelfTest | tail -3

echo
echo "== differential test against pycryptodome (AES-SIV + AES-GCM) =="
python3 tools/interop.py "$jdk8/bin/java" build/classes:build/test-classes build/tmp

echo
echo "== TLA+ model: no key in the Java heap =="
cd verify
# Not committed: a 4.3 MB jar is a download, not source.
if [ ! -f tla2tools.jar ]; then
    curl -sSfL -o tla2tools.jar \
        https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
fi
"$jdkmod/bin/java" -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC \
    -config MC.cfg -workers "$(nproc)" MC.tla > tlc-safe.log 2>&1
grep -E 'No error has been found|states generated' tlc-safe.log
echo "-- negative control: the same model with the leak action enabled must fail --"
if "$jdkmod/bin/java" -XX:+UseParallelGC -cp tla2tools.jar tlc2.TLC \
    -config MCBug.cfg -workers "$(nproc)" MC.tla > tlc-bug.log 2>&1; then
    echo "FAIL: the model did not detect the leak it is capable of expressing"
    exit 1
fi
grep -E 'Invariant NoKeyInHeap is violated' tlc-bug.log
cd ..

echo
echo "== bytecode gate: no heap-carrier field, no SecretKeySpec/Cipher =="
JAVAP=$javap tools/check-bytecode.sh build/classes

echo
echo "== heap-dump scan: live key never appears in the heap =="
tools/heap-scan.sh "$jdk8"

echo
echo "== field encryption against a real database =="
tools/demo-field-encryption.sh | tail -2
