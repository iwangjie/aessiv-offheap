#!/usr/bin/env bash
# Empirical half of the verification: take a live heap dump while a key is in use, then search the
# dump for the key bytes. Runs the library and a deliberately leaky control through the same
# pipeline so the negative result is meaningful.
#
#   clean   = SivKey holds the key; expected hits = 0
#   control = byte[] field holds the key; expected hits > 0
#
# Usage: tools/heap-scan.sh [jdk8-home]
set -euo pipefail

jdk=${1:-${JDK8:-/usr/lib/jvm/java-8-openjdk}}
cd "$(dirname "$0")/.."

classes=build/classes
tests=build/test-classes
work=build/heapscan
rm -rf "$work"
mkdir -p "$work"

# A random 32-byte key, written once and used by both runs. Written with dd so it is a file, not a
# shell variable that would leak into the environment of later processes.
keyfile=$work/key.bin
dd if=/dev/urandom of="$keyfile" bs=32 count=1 status=none
echo "key file: $keyfile ($(wc -c <"$keyfile" | tr -d ' ') bytes)"

run_case() {
    local name=$1 dump=$work/$1.hprof
    shift
    echo
    echo "=== $name ==="
    "$jdk/bin/java" -Xmx64m -cp "$classes:$tests" "$@" >"$work/$name.log" 2>&1 &
    local pid=$!
    # Wait for the program to report that the key is live and it is parked.
    for _ in $(seq 1 100); do
        grep -q READY "$work/$name.log" 2>/dev/null && break
        sleep 0.1
    done
    grep READY "$work/$name.log" || { echo "program never became ready"; kill $pid; return 1; }
    "$jdk/bin/jmap" -dump:live,format=b,file="$dump" "$pid" >"$work/$name.jmap.log" 2>&1
    kill $pid 2>/dev/null || true
    wait $pid 2>/dev/null || true
    echo "dump: $dump ($(wc -c <"$dump" | tr -d ' ') bytes)"
    python3 tools/scan_heap.py "$dump" "$keyfile" || true
}

# The clean run must find nothing; the control must find something. Both verdicts are asserted, so
# a broken scanner fails as loudly as a leaking library.
clean_hits=$(run_case clean dev.offheap.siv.SivSelfTest --dump-key "$keyfile" |
    sed -n 's/^total hits=//p')
control_hits=$(run_case control dev.offheap.siv.LeakyControl "$keyfile" |
    sed -n 's/^total hits=//p')

echo
echo "verdict: clean=$clean_hits control=$control_hits"
if [ "$clean_hits" != "0" ]; then
    echo "FAIL: the library leaked key material into the heap ($clean_hits hits)"
    exit 1
fi
if [ "$control_hits" -lt 1 ]; then
    echo "FAIL: the scanner cannot find a key it is known to be able to find"
    exit 1
fi
echo "PASS: live key absent from the dump; control detected"
