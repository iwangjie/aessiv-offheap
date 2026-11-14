#!/usr/bin/env python3
"""Scan an HPROF heap dump for the bytes of a secret key.

Two runs are expected:

  clean   - dev.offheap.siv.SivSelfTest --dump-key holds a live SivKey and never yields its bytes,
            so the key must appear 0 times.
  control - dev.offheap.siv.LeakyControl keeps the key in a byte[] field, so it must appear.

Without the control, "0 hits" could just mean the scanner is broken.

The scan is a raw byte search over the whole dump. That is deliberately stronger than parsing the
record structure: it covers primitive-array bodies (byte[]), String payloads, and any other place
HPROF copies bytes, and it cannot miss data by misparsing a record. A 16-byte random key cannot
occur by accident in a 20 MB dump, so hits are unambiguous.

Needles: the full key, each key half, the first 8 bytes of each half. A partial copy - a JCE
SecretKeySpec's clone, a truncated stack fragment - is therefore caught too.

Usage: tools/scan_heap.py <dump.hprof> <keyfile>
"""
import sys

from Crypto.Cipher import AES


def dbl(v):
    n = int.from_bytes(v, "big") << 1
    if n >> 128:
        n = (n & ((1 << 128) - 1)) ^ 0x87
    return n.to_bytes(16, "big")


def derived_needles(key):
    """Key-derived material that must never surface on the heap either.

    * CMAC subkeys K1/K2 of the S2V half: E(K1,0) doubled twice. Reading either recovers the S2V
      key's outputs.
    * The GCM GHASH subkey H = E(K,0^128): reading it lets an attacker forge tags.

    Computing them here, independently of the library under test, is what makes the scan meaningful
    for a derived value rather than just for the raw key.
    """
    needles = {}
    half = len(key) // 2
    l = AES.new(key[:half], AES.MODE_ECB).encrypt(bytes(16))
    k1 = dbl(l)
    k2 = dbl(k1)
    needles["S2V subkey K1 (%d B)" % half] = k1
    needles["S2V subkey K2 (%d B)" % half] = k2
    if len(key) in (16, 24, 32):
        needles["GCM H (%d B)" % len(key)] = AES.new(key, AES.MODE_ECB).encrypt(bytes(16))
    return needles


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    dump_path, key_path = sys.argv[1], sys.argv[2]
    key = open(key_path, "rb").read()
    if len(key) < 16:
        raise SystemExit("key shorter than 16 bytes")

    half = len(key) // 2
    needles = {
        "full key (%d B)" % len(key): key,
        "first half (%d B)" % half: key[:half],
        "second half (%d B)" % half: key[half:],
        "first 8 B": key[:8],
        "4th 8 B": key[24:32],
    }
    needles.update(derived_needles(key))
    if half >= 16:
        needles["CTR half (%d B)" % half] = key[half:]

    with open(dump_path, "rb") as fh:
        dump = fh.read()

    total = 0
    print("dump=%s size=%d B" % (dump_path, len(dump)))
    for label, needle in needles.items():
        hits = dump.count(needle)
        total += hits
        print("  %-18s hits=%d" % (label, hits))
    print("total hits=%d" % total)
    return 0 if total == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
