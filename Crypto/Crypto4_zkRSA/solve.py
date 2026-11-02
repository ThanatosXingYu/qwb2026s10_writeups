#!/usr/bin/env python3
"""zkRSA solver: transcript collection + modulus / exponent recovery.

The service (task.py) implements a GQ identification protocol with e = 2
for the [P] menu entry and a *broken* verifier for the [V] entry:

    com  = r^2 mod n                     (r = next output of ECGenerator)
    chal = sha256(f"{com}||{y}||{n}||{e}") % 2
    res  = r * x^chal mod n

    [V] y   = pow(bytes_to_long(FLAG), x, n)
        com = int(input("com>"))
        chal = next(gen) % x
        res = int(input("res>"))
        assert pow(res, x, n) == com * pow(y, chal, n) % n

Since every [P] proof satisfies

    res^2 - com = r^2 * (x^(2*chal) - 1) == 0 (mod n),

the modulus is n = gcd_i(res_i^2 - com_i), valid for chal = 0 *and*
chal = 1 (for chal = 0 the relation is res^2 - com = 0 exactly).  With n
known, every challenge-1 proof yields

    x^2 = res^2 * com^-1 mod n,

which is the only public handle on the hidden exponent.  The forgery itself
is

    com = y^(-chal) mod n,  res = 1

which makes both sides of the verification equal to 1; it needs the
predicted value of `chal = next(gen) % x`, i.e. the hidden exponent x and
the 16 possible next x-coordinates of the ECGenerator walk.

This script implements the algebraic half of the chain: the proof-of-work,
transcript collection, recovery of n, recovery of x^2 mod n, per-record
verification and the forgery equation.  Recovering the ECGenerator model
itself (a, b and the 16 translation points) is worked out in the write-up
and not reimplemented here.  Run with --self-test to check the recovery and
the forgery algebra offline.

Usage:
    python solve.py --host 1.2.3.4 --port 9999 --proofs 336 --out records.json
    python solve.py --records records.json          # offline re-analysis
    python solve.py --self-test
"""

import argparse
import hashlib
import json
import math
import random
import re
import socket
import string
import sys
import time

ALPHABET = string.ascii_letters + string.digits


# --------------------------------------------------------------------------
# number helpers
# --------------------------------------------------------------------------
def is_probable_prime(n, rounds=24, rng=None):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    rng = rng or random.Random()
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits, rng, mod4=None):
    while True:
        cand = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if mod4 is not None and cand % 4 != mod4:
            continue
        if is_probable_prime(cand, rng=rng):
            return cand


def invert(a, n):
    """Modular inverse that tolerates non-units (returns None)."""
    a %= n
    if a == 0:
        return None
    g, x = math.gcd(a, n), None
    try:
        x = pow(a, -1, n)
    except ValueError:
        return None
    if g != 1 or x is None:
        return None
    return x


# --------------------------------------------------------------------------
# transcript analysis (write-up 3.1)
# --------------------------------------------------------------------------
def recover_n(records, verbose=True):
    """n = gcd of (res^2 - com) over the challenge-0 proofs.

    For chal = 0 we have res = r and com = r^2 mod n, hence
    res^2 - com = n * floor(r^2 / n) is an exact multiple of n.  (For
    chal = 1 the difference is r^2*(x^2 - 1), which is *not* a multiple
    of n in general - the write-up's remark that those records can be
    used as well does not hold, so they are skipped here.)
    """
    deltas = [(res * res - com) for com, chal, res in records if chal == 0]
    if len(deltas) < 3:
        raise ValueError("need at least 3 challenge-0 proofs to recover n "
                         "(got %d)" % len(deltas))
    n = 0
    for d in deltas:
        n = math.gcd(n, abs(d))
        if n == 1:
            break
    if n <= 1:
        raise ValueError("gcd of (res^2 - com) collapsed to 1; "
                         "need more proofs")
    # the gcd is n times gcd_i(floor(r_i^2/n)); strip small cofactors if any
    while n > 1:
        for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
            if n % p == 0 and n // p > 2:
                n //= p
                break
        else:
            break
    if verbose:
        print("[*] recovered n with %d bits from %d challenge-0 records"
              % (n.bit_length(), len(deltas)))
    return n


def analyse(records, verbose=True):
    """Recover n and x^2 mod n and verify every record against them."""
    n = recover_n(records, verbose=verbose)
    if n.bit_length() < 500:
        print("[!] n is smaller than expected (512-bit modulus)")

    zero = [(com, res) for com, chal, res in records if chal == 0]
    if verbose:
        print("[*] challenge-0 records: %d (res is the raw EC x-coordinate, "
              "res^2 == com: %d)" % (len(zero),
                                     sum(1 for com, res in zero
                                         if res * res % n == com)))

    x2 = None
    for com, chal, res in records:
        if chal != 1:
            continue
        inv = invert(com, n)
        if inv is None:
            continue
        cand = res * res % n * inv % n
        if x2 is None:
            x2 = cand
        elif cand != x2:
            print("[!] inconsistent x^2 between challenge-1 records")
        # a single record is enough; keep looping only for the check
    if x2 is None:
        print("[!] no challenge-1 record, x^2 mod n unavailable")
        return n, None

    y0 = x2                                   # y used by the [P] proofs
    ok = sum(1 for com, chal, res in records
             if pow(res, 2, n) == com * pow(y0, chal, n) % n)
    if verbose:
        print("[*] x^2 mod n = %d" % x2)
        print("[*] all records satisfy res^2 == com * y^chal: %d/%d"
              % (ok, len(records)))
    return n, x2


def forge(n, y, chal):
    """Write-up 3.5: com = y^-chal, res = 1 passes verification."""
    com = pow(y, -chal, n)
    res = 1
    assert 0 < com < n and 0 < res < n
    return com, res


# --------------------------------------------------------------------------
# protocol client
# --------------------------------------------------------------------------
class Client:
    def __init__(self, host, port, timeout=30.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""

    def recv_until(self, suffix):
        while not self.buf.endswith(suffix):
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError("connection closed while waiting for %r" % suffix)
            self.buf += chunk
        data, self.buf = self.buf, b""
        return data

    def sendline(self, line):
        self.sock.sendall((str(line) + "\n").encode())

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def solve_pow(banner):
    m = re.search(r"sha256\(XXXX \+ (\S+)\) == ([0-9a-f]{64})", banner)
    if not m:
        return None
    suffix, target = m.group(1), m.group(2)
    pre = (suffix + "").encode()
    for a in ALPHABET:
        for b in ALPHABET:
            for c in ALPHABET:
                for d in ALPHABET:
                    cand = (a + b + c + d)
                    if hashlib.sha256(cand.encode() + pre).hexdigest() == target:
                        return cand
    return None


def collect(host, port, proofs, timeout=60.0):
    cli = Client(host, port, timeout=timeout)
    banner = cli.recv_until(b"XXXX>")
    print("[*] banner:", banner.decode(errors="replace").strip().replace("\n", " | "))
    prefix = solve_pow(banner.decode(errors="replace"))
    if prefix is None:
        raise RuntimeError("proof of work not solved")
    print("[*] pow =", prefix)
    cli.sendline(prefix)

    records = []
    for _ in range(proofs):
        cli.recv_until(b">")              # menu prompt
        cli.sendline("p")
        out = cli.recv_until(b"\n")
        m = re.search(r"proof = \((\d+), (\d+), (\d+)\)", out.decode(errors="replace"))
        if not m:
            raise RuntimeError("unparsable proof line: %r" % out[:120])
        records.append((int(m.group(1)), int(m.group(2)), int(m.group(3))))
        if (len(records) % 25) == 0:
            print("[*] collected %d proofs" % len(records), flush=True)
    cli.close()
    return records


def self_test(rounds=60, seed=None):
    """Emulate the transcript (r random, e = 2) and check the algebra."""
    rng = random.Random(seed)
    p = gen_prime(256, rng, mod4=3)
    q = gen_prime(256, rng, mod4=3)
    n = p * q
    x = rng.randrange(1, n - 1)
    y0 = pow(x, 2, n)

    records = []
    for _ in range(rounds):
        r = rng.randrange(2, n)
        com = pow(r, 2, n)
        chal = int(hashlib.sha256(
            f"{com}||{y0}||{n}||2".encode()).hexdigest(), 16) % 2
        res = r * pow(x, chal, n) % n
        records.append((com, chal, res))

    n2, x2 = analyse(records)
    print("[*] n recovered exactly:", n2 == n)
    print("[*] x^2 recovered exactly:", x2 == pow(x, 2, n))

    # the forgery: y = m^x for an arbitrary message m
    m = int.from_bytes(b"flag{self_test}", "big")
    y = pow(m, x, n)
    chal = rng.randrange(0, x)
    com, res = forge(n, y, chal)
    lhs = pow(res, x, n)
    rhs = com * pow(y, chal, n) % n
    print("[*] forgery accepted by the verifier:", lhs == rhs == 1)
    return n2 == n and x2 == pow(x, 2, n) and lhs == rhs


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="zkRSA solver (collection + recovery)")
    ap.add_argument("--host")
    ap.add_argument("--port", type=int)
    ap.add_argument("--proofs", type=int, default=336)
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--out", default="records.json")
    ap.add_argument("--records", help="analyse a previously saved transcript")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        ok = self_test()
        return 0 if ok else 1

    if args.records:
        with open(args.records, "r", encoding="utf-8") as f:
            raw = json.load(f)
        records = [tuple(t) for t in raw]
        analyse(records)
        return 0

    if not args.host or not args.port:
        ap.error("need --host/--port, or --records, or --self-test")

    t0 = time.time()
    records = collect(args.host, args.port, args.proofs, timeout=args.timeout)
    print("[*] collection took %.1fs" % (time.time() - t0))
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(records, f)
    print("[*] transcript written to %s" % args.out)
    analyse(records)
    print("[!] the remaining step (ECGenerator model, write-up 3.2-3.4) is "
          "not implemented; see the module docstring")
    return 0


if __name__ == "__main__":
    sys.exit(main())
