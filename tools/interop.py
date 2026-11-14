#!/usr/bin/env python3
"""Differential test: this library vs pycryptodome, for AES-SIV and AES-GCM.

Both pycryptodome modes implement the specifications directly (RFC 5297 and NIST SP 800-38D), so
agreement over randomized cases is evidence the MAC, the doubling, the counter layout, the key split
and GHASH are all right.

Output ordering differs between the two and is easy to get wrong:

  SIV: RFC 5297 emits Z = V || C. pycryptodome returns (ciphertext, tag), so we reassemble tag first.
  GCM: SP 800-38D emits C || T, which is also pycryptodome's (ciphertext, tag) order.

Usage: tools/interop.py <path-to-java> <classpath> <workdir>
"""
import os
import random
import subprocess
import sys

from Crypto.Cipher import AES


def siv_reference(key, nonce, ad, pt):
    kwargs = {"nonce": nonce} if nonce is not None else {}
    cipher = AES.new(key, AES.MODE_SIV, **kwargs)
    for component in ad:
        cipher.update(component)
    ciphertext, tag = cipher.encrypt_and_digest(pt)
    return tag + ciphertext


def gcm_reference(key, iv, ad, pt):
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    for component in ad:
        cipher.update(component)
    ciphertext, tag = cipher.encrypt_and_digest(pt)
    return ciphertext + tag


RFC_A1 = dict(
    alg="siv",
    key=bytes.fromhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
    iv=None,
    ad=[bytes.fromhex("101112131415161718191a1b1c1d1e1f2021222324252627")],
    pt=bytes.fromhex("112233445566778899aabbccddee"),
)

RFC_A2 = dict(
    alg="siv",
    key=bytes.fromhex("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f"),
    iv=bytes.fromhex("09f911029d74e35bd84156c5635688c0"),
    ad=[
        bytes.fromhex(
            "00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"
        ),
        bytes.fromhex("102030405060708090a0"),
    ],
    pt=bytes.fromhex(
        "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553"
    ),
)

# NIST GCM test cases 13-16, AES-256.
GCM_K256 = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
GCM_IV = bytes.fromhex("cafebabefacedbaddecaf888")
GCM_PT60 = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
)
GCM_CASES = [
    dict(alg="gcm", key=bytes(32), iv=bytes(12), ad=[], pt=b""),
    dict(alg="gcm", key=bytes(32), iv=bytes(12), ad=[], pt=bytes(16)),
    dict(alg="gcm", key=GCM_K256, iv=GCM_IV, ad=[], pt=GCM_PT60),
    dict(
        alg="gcm",
        key=GCM_K256,
        iv=GCM_IV,
        ad=[bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")],
        pt=GCM_PT60,
    ),
]


def build_cases():
    cases = [RFC_A1, RFC_A2] + GCM_CASES
    rng = random.Random(20240607)

    for _ in range(200):
        key_len = rng.choice([32, 48, 64])
        cases.append(
            dict(
                alg="siv",
                key=bytes(rng.randrange(256) for _ in range(key_len)),
                iv=(bytes(rng.randrange(256) for _ in range(rng.choice([1, 8, 16, 17])))
                    if rng.random() < 0.5 else None),
                ad=[
                    bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 15, 16, 17, 32, 63])))
                    for _ in range(rng.choice([0, 1, 2, 3]))
                ],
                pt=bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 15, 16, 17, 31, 64, 129]))),
            )
        )

    for _ in range(200):
        key_len = rng.choice([16, 24, 32])
        cases.append(
            dict(
                alg="gcm",
                key=bytes(rng.randrange(256) for _ in range(key_len)),
                iv=bytes(rng.randrange(256) for _ in range(12)),
                ad=[
                    bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 15, 16, 17, 32, 63])))
                    for _ in range(rng.choice([0, 1, 2, 3]))
                ],
                pt=bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 15, 16, 17, 31, 64, 129]))),
            )
        )
    return cases


def reference(case):
    if case["alg"] == "siv":
        return siv_reference(case["key"], case["iv"], case["ad"], case["pt"])
    return gcm_reference(case["key"], case["iv"], case["ad"], case["pt"])


def main():
    java, classpath, workdir = sys.argv[1], sys.argv[2], sys.argv[3]
    cases = build_cases()

    for case in cases:
        case["want"] = reference(case)

    lines = []
    for case in cases:
        lines.append(
            "\t".join(
                [
                    case["alg"],
                    case["key"].hex(),
                    "-" if case["iv"] is None else case["iv"].hex(),
                    str(len(case["ad"])),
                ]
                + [c.hex() for c in case["ad"]]
                + [case["pt"].hex()]
            )
        )
    src = os.path.join(workdir, "cases.tsv")
    dst = os.path.join(workdir, "cases.out")
    with open(src, "w") as fh:
        fh.write("\n".join(lines) + "\n")

    subprocess.run([java, "-cp", classpath, "dev.offheap.siv.InteropRunner", src, dst], check=True)

    with open(dst) as fh:
        got = fh.read().split()

    failures = 0
    for case, produced in zip(cases, got):
        if bytes.fromhex(produced) != case["want"]:
            failures += 1
            print("MISMATCH alg=%s key=%s iv=%s ad=%d pt=%d"
                  % (case["alg"], case["key"].hex(),
                     "-" if case["iv"] is None else case["iv"].hex(),
                     len(case["ad"]), len(case["pt"])))

    siv = sum(1 for c in cases if c["alg"] == "siv")
    print("cases=%d (siv=%d gcm=%d) matched=%d mismatched=%d"
          % (len(cases), siv, len(cases) - siv, len(cases) - failures, failures))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
