"""Open the Hexachord finale from credited chapter receipts.

`gift.elf` uses one degree-17 Shamir polynomial per AES-256 key byte over
GF(2^8) with the field polynomial 0x11d.  It prints each 33-byte
receipt as chapter tag || 32 evaluations and `flag.enc` as nonce(12) || ciphertext ||
GCM tag(16).  The AES-GCM tag authenticates both share reconstruction and
the encrypted flag; fewer than 18 shares cannot pass that check.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


HEX_SHARE = re.compile(r"^[0-9a-fA-F]{66}$")
ENC_RE = re.compile(rb"flag\.enc:\s*([0-9a-fA-F]+)")


def gf_mul(a: int, b: int) -> int:
    """Multiply two GF(2^8) elements modulo x^8+x^4+x^3+x^2+1."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1D
        b >>= 1
    return result


def gf_pow(a: int, exponent: int) -> int:
    result = 1
    while exponent:
        if exponent & 1:
            result = gf_mul(result, a)
        a = gf_mul(a, a)
        exponent >>= 1
    return result


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("GF256 inverse of zero")
    return gf_pow(a, 254)


def recover_key(shares: list[bytes]) -> bytes:
    """Lagrange-interpolate the 32 key bytes at x=0 from 18 shares."""
    if len(shares) < 18:
        raise ValueError(f"need 18 distinct shares; got {len(shares)}")
    distinct: dict[int, bytes] = {}
    for share in shares:
        if len(share) != 33 or share[0] == 0:
            raise ValueError("each share must be 33 bytes with nonzero x")
        x = share[0]
        if x in distinct and distinct[x] != share:
            raise ValueError(f"conflicting shares at x={x}")
        distinct[x] = share
    if len(distinct) < 18:
        raise ValueError(f"need 18 distinct x values; got {len(distinct)}")
    selected = list(distinct.values())[:18]
    weights: list[int] = []
    for i, own in enumerate(selected):
        xi = own[0]
        weight = 1
        for j, other in enumerate(selected):
            if i == j:
                continue
            xj = other[0]
            weight = gf_mul(weight, gf_mul(xj, gf_inv(xi ^ xj)))
        weights.append(weight)
    key = bytearray(32)
    for share, weight in zip(selected, weights):
        for index, y in enumerate(share[1:]):
            key[index] ^= gf_mul(y, weight)
    return bytes(key)


def decrypt(enc: bytes, shares: list[bytes]) -> bytes:
    if len(enc) < 29:
        raise ValueError("flag.enc needs 12-byte nonce, ciphertext and 16-byte tag")
    key = recover_key(shares)
    return AESGCM(key).decrypt(enc[:12], enc[12:], None)


def load_records(path: Path) -> list[bytes]:
    shares: list[bytes] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        record = json.loads(line)
        fragment = record.get("fragment")
        if fragment is None:
            continue
        if record.get("status") not in ("credited", "final_received"):
            raise ValueError(f"uncredited fragment in chapter {record.get('chapter')}")
        if not HEX_SHARE.fullmatch(fragment):
            raise ValueError(f"malformed fragment in chapter {record.get('chapter')}")
        share = bytes.fromhex(fragment)
        # The first byte is retained as a chapter receipt.  The interpolation
        # table uses the order in which credited receipts were collected.
        shares.append(bytes([len(shares) + 1]) + share[1:])
    return shares


def load_final(path: Path) -> bytes:
    raw = path.read_bytes()
    match = ENC_RE.search(raw)
    if match is None:
        raise ValueError("no flag.enc hex in final response")
    enc = bytes.fromhex(match.group(1).decode("ascii"))
    return enc


def selftest() -> None:
    """Exercise the exact interpolation and AES-GCM framing with known data."""
    key = bytes(range(32))
    coeffs = [[key[j]] + [((j * 37 + d * 19) & 0xFF)
                          for d in range(1, 18)] for j in range(32)]
    shares = []
    for x in range(1, 21):
        share = bytearray([x])
        for row in coeffs:
            value = row[-1]
            for coefficient in reversed(row[:-1]):
                value = gf_mul(value, x) ^ coefficient
            share.append(value)
        shares.append(bytes(share))
    assert recover_key(shares[:18]) == key
    assert recover_key(shares[2:20]) == key
    nonce = bytes(range(12))
    plaintext = b"flag{synthetic-gift-roundtrip}"
    enc = nonce + AESGCM(key).encrypt(nonce, plaintext, None)
    assert decrypt(enc, shares[1:19]) == plaintext
    print("selftest OK: 18-of-20 GF256 reconstruction and AES-GCM tag")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", type=Path)
    parser.add_argument("--final", type=Path)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    if args.selftest:
        selftest()
        return
    if args.records is None or args.final is None:
        parser.error("--records and --final are required")
    shares = load_records(args.records)
    enc = load_final(args.final)
    print("shares", len(shares), "enc_bytes", len(enc))
    plaintext = decrypt(enc, shares)
    print("plaintext_hex", plaintext.hex())
    print("plaintext_utf8", plaintext.decode("utf-8"))



