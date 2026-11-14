#!/usr/bin/env bash
# Field-level encryption against a real SQLite database: 23 assertions covering search on encrypted
# columns, row binding, what deterministic mode leaks, rotation, and key retirement.
#
# Downloads a JDBC driver into build/ on first run. Everything else is this repository's own code.
set -euo pipefail
cd "$(dirname "$0")/.."

jdk8=${JDK8:-/usr/lib/jvm/java-8-openjdk}
lib=build/demo-lib
classes=build/demo-classes

sqlite_version=3.50.3.0
slf4j_version=2.0.17
sqlite_jar=$lib/sqlite-jdbc-$sqlite_version.jar
slf4j_api=$lib/slf4j-api-$slf4j_version.jar
slf4j_nop=$lib/slf4j-nop-$slf4j_version.jar

mkdir -p "$lib" "$classes"
fetch() {
    [ -f "$2" ] || curl -sSfL -o "$2" "https://repo1.maven.org/maven2/$1"
}
fetch "org/xerial/sqlite-jdbc/$sqlite_version/sqlite-jdbc-$sqlite_version.jar" "$sqlite_jar"
fetch "org/slf4j/slf4j-api/$slf4j_version/slf4j-api-$slf4j_version.jar" "$slf4j_api"
fetch "org/slf4j/slf4j-nop/$slf4j_version/slf4j-nop-$slf4j_version.jar" "$slf4j_nop"

"$jdk8/bin/javac" -cp build/classes -d "$classes" \
    demo/src/main/java/dev/offheap/siv/demo/*.java 2>&1 | grep -F ': error:' && exit 1

"$jdk8/bin/java" -cp "build/classes:$classes:$sqlite_jar:$slf4j_api:$slf4j_nop" \
    dev.offheap.siv.demo.FieldEncryptionDemo
