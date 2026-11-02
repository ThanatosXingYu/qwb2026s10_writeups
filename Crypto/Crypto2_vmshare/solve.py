#!/usr/bin/env python3
"""vmshare solver (3-lane meet-in-the-middle).

The binary `encryptor` is a tiny ARX block cipher:
  * state  = 32 bytes "SIMD_TINY_BLOCK_IS_A_NIGHTMARE!!" read as 16 LE uint16 lanes
  * two calls of an 8-round lane-wise permutation, keyed by the two 24-bit
    halves of flag{<hex7>_<hex7>} (key schedule masks with 0xffffff)
  * each round (per lane j, with fixed lane constant C_j and round key k_i):
        y = (k_i + C_j + rol16(x, 3)) mod 2^16
        y ^= y >> 7
        y = rol16(y, 9)
        y ^= y >> 5                    (omitted in the 8th round)
        x = y
    and every 8-round call starts with x ^= x >> 5.

Because lanes never interact, a 48-bit fingerprint made of the first three
lanes is enough to join the two 2^24 key spaces: build a table of
forward(X) fingerprints from the plaintext state, then walk Y backwards
from the ciphertext and look the fingerprint up.  A hit is confirmed by a
full 16-lane encryption.

Usage:
    python solve.py --cipher cipher.bin
    python solve.py --cipher cipher.bin --xmin 0x170000 --xmax 0x180000

Only numpy is required.
"""

import argparse
import sys

import numpy as np

MASK32 = np.uint64(0xFFFFFFFF)
MASK16 = np.uint64(0xFFFF)

INIT = b"SIMD_TINY_BLOCK_IS_A_NIGHTMARE!!"
LANE_C = [0x1357, 0x2468, 0x369c, 0x48ad, 0x5be1, 0x6cf2, 0x7d03, 0x8e14,
          0x9f25, 0xa036, 0xb147, 0xc258, 0xd369, 0xe47a, 0xf58b, 0x069c]
SEED_X = 0x31415926
SEED_Y = 0x27182818
KEYSPACE = 1 << 24


# --------------------------------------------------------------------------
# key schedule (sub_1c60)
# --------------------------------------------------------------------------
def schedule(v, seed):
    h = ((int(v) & 0xFFFFFF) ^ seed) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 0x45D9F3B) & 0xFFFFFFFF
    h ^= h >> 16
    keys = []
    for i in range(8):
        h = (h + i * 0x7F4A7C15 + 0x9E3779B9) & 0xFFFFFFFF
        h2 = h
        h2 ^= h2 >> 13
        h2 = (h2 * 0x85EBCA6B) & 0xFFFFFFFF
        h2 ^= h2 >> 16
        keys.append((h2 ^ (h2 >> 16)) & 0xFFFF)
        h = h2
    return keys


def schedule_vec(v, seed):
    """Same schedule, vectorised over an array of candidate values."""
    h = (v & np.uint64(0xFFFFFF)) ^ np.uint64(seed)
    h = h & MASK32
    h ^= h >> np.uint64(13)
    h = (h * np.uint64(0x45D9F3B)) & MASK32
    h ^= h >> np.uint64(16)
    out = []
    for i in range(8):
        h = (h + np.uint64(i * 0x7F4A7C15 + 0x9E3779B9)) & MASK32
        h2 = h
        h2 ^= h2 >> np.uint64(13)
        h2 = (h2 * np.uint64(0x85EBCA6B)) & MASK32
        h2 ^= h2 >> np.uint64(16)
        out.append((h2 ^ (h2 >> np.uint64(16))) & MASK16)
        h = h2
    return out


# --------------------------------------------------------------------------
# lane primitives
# --------------------------------------------------------------------------
def rol(x, n):
    return ((x << np.uint64(n)) | (x >> np.uint64(16 - n))) & MASK16


def ror(x, n):
    return ((x >> np.uint64(n)) | (x << np.uint64(16 - n))) & MASK16


def unxor_r(y, n):
    """Invert x -> x ^ (x >> n) (triangular map, converges in 16/n + 1 steps)."""
    x = y.copy()
    for _ in range(16 // n + 1):
        x = y ^ (x >> np.uint64(n))
    return x & MASK16


def forward(lanes, keys, c):
    """One 8-round call. lanes: (N, nl) uint64, keys: list of 8 arrays (N, 1)."""
    x = (lanes ^ (lanes >> np.uint64(5))) & MASK16
    for i in range(8):
        y = (keys[i] + c[None, :] + rol(x, 3)) & MASK16
        y ^= y >> np.uint64(7)
        y = rol(y, 9)
        if i != 7:                       # the last round omits the tail xor
            y ^= y >> np.uint64(5)
        x = y
    return x


def backward(lanes, keys, c):
    """Inverse of forward() for one 8-round call."""
    y = lanes & MASK16
    for i in range(7, -1, -1):
        if i != 7:
            y = unxor_r(y, 5)
        y = ror(y, 9)
        y = unxor_r(y, 7)
        y = (y - keys[i] - c[None, :]) & MASK16
        y = ror(y, 3)
    return unxor_r(y, 5)


def fingerprint(lanes):
    return (lanes[:, 0] | (lanes[:, 1] << np.uint64(16))
            | (lanes[:, 2] << np.uint64(32)))


# --------------------------------------------------------------------------
# full cipher (16 lanes) - used to confirm a hit
# --------------------------------------------------------------------------
def encrypt(block, vx, vy):
    st = np.frombuffer(block, dtype="<u2").astype(np.uint64)
    for k in (schedule(vx, SEED_X), schedule(vy, SEED_Y)):
        keys = [np.full(1, t, dtype=np.uint64) for t in k]
        st = forward(st[None, :], keys, np.array(LANE_C, dtype=np.uint64))[0]
    return st.astype("<u2").tobytes()


def build_forward_table(state, lo, hi, step, verbose=True):
    nl = 3
    lanes0 = np.broadcast_to(state[:nl], (1, nl)).astype(np.uint64)
    lane_c = np.array(LANE_C[:nl], dtype=np.uint64)
    table = np.empty(hi - lo, dtype=np.uint64)
    for base in range(lo, hi, step):
        n = min(step, hi - base)
        v = np.arange(base, base + n, dtype=np.uint64)
        keys = [k.reshape(-1, 1) for k in schedule_vec(v, SEED_X)]
        lanes = np.broadcast_to(lanes0, (n, nl)).copy()
        table[base - lo:base - lo + n] = fingerprint(forward(lanes, keys, lane_c))
        if verbose:
            print("[*] forward %d/%d" % (base - lo + n, hi - lo), flush=True)
    return table


def main():
    ap = argparse.ArgumentParser(description="vmshare meet-in-the-middle solver")
    ap.add_argument("--cipher", default="cipher.bin", help="path to cipher.bin")
    ap.add_argument("--step", type=int, default=1 << 20, help="vectorised chunk size")
    ap.add_argument("--xmin", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--xmax", type=lambda s: int(s, 0), default=KEYSPACE)
    ap.add_argument("--ymin", type=lambda s: int(s, 0), default=0)
    ap.add_argument("--ymax", type=lambda s: int(s, 0), default=KEYSPACE)
    ap.add_argument("--max-hits", type=int, default=8)
    ap.add_argument("--nibble", type=lambda s: int(s, 16), default=3,
                    help="free top nibble used for the platform flag form")
    args = ap.parse_args()

    with open(args.cipher, "rb") as f:
        block = f.read()
    if len(block) != 32:
        ap.error("cipher.bin must be 32 bytes")

    state = np.frombuffer(INIT, dtype="<u2").astype(np.uint64)
    ct = np.frombuffer(block, dtype="<u2").astype(np.uint64)

    table = build_forward_table(state, args.xmin, args.xmax, args.step)
    order = np.argsort(table)
    stable = table[order]

    nl = 3
    ct3 = np.broadcast_to(ct[:nl], (1, nl)).astype(np.uint64)
    lane_c = np.array(LANE_C[:nl], dtype=np.uint64)

    found = 0
    for base in range(args.ymin, args.ymax, args.step):
        n = min(args.step, args.ymax - base)
        v = np.arange(base, base + n, dtype=np.uint64)
        keys = [k.reshape(-1, 1) for k in schedule_vec(v, SEED_Y)]
        lanes = np.broadcast_to(ct3, (n, nl)).copy()
        fp = fingerprint(backward(lanes, keys, lane_c))
        pos = np.searchsorted(stable, fp)
        pos[pos >= stable.size] = 0
        hit = stable[pos] == fp
        for idx in np.nonzero(hit)[0][:args.max_hits]:
            x = args.xmin + int(order[pos[idx]])
            y = base + int(idx)
            ok = encrypt(INIT, x, y) == block
            print("[*] candidate X=%#x Y=%#x cipher-ok=%s" % (x, y, ok), flush=True)
            if ok:
                found += 1
                print("[+] flag = flag{%07x_%07x}" % (x, y), flush=True)
                print("[!] the key schedule masks with 0xffffff, so the top hex "
                      "nibble of each half is free; the platform form is "
                      "flag{%x%06x_%x%06x}" % (args.nibble, x & 0xFFFFFF,
                                                args.nibble, y & 0xFFFFFF),
                      flush=True)
        print("[*] backward %d/%d" % (base - args.ymin + n, args.ymax - args.ymin),
              flush=True)

    if not found:
        print("[-] no candidate reproduced cipher.bin", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
