#!/usr/bin/env python3
"""hoRRibleRing solver: per-bit decisional Ring-LWE via uSVP + BKZ.

task.sage emits one sample per flag bit (MSB first):
  bit 0 -> (a, b = a*s + e mod f) with s, e discrete Gaussian (sigma=3.371)
  bit 1 -> (a, b) uniform in R_p^2
with p = 0x3ac01f87, n = deg f = 512, f smooth over F_p.

For a sample the lattice
        [ p*I   0   0 ]
    B = [ M_a   I   0 ]        det = p^n,  rank 2n+1
        [  b    0   K ]
(Kannan embedding, K = 1) contains the vector (e, -s, K) of norm
~sqrt(2n)*sigma ~ 108 while the Gaussian heuristic is ~2.4e5, so it is an
extreme uSVP instance: LLL is hopeless, BKZ with block size ~80-120 pulls
the vector out.  A row of the reduced basis with last coordinate +-1 is
accepted only if, after re-computing e = b - a*s mod f and centering,
both max|s_i| and max|e_i| are <= BOUND (= 40 = 12*sigma); otherwise the
sample is declared F1 (bit 1).

Usage:
    python solve.py --sage task.sage --samples samples.txt --bkz 80
    python solve.py --sage task.sage --samples samples.txt --bkz 120 \
                    --jobs 8 --start 0 --end 336 --out bits.json

Requires fpylll (and numpy for the fast a*s mod f).
"""

import argparse
import ast
import json
import re
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np

try:
    from fpylll import BKZ, IntegerMatrix, LLL
    HAVE_FPYLLL = True
except ImportError:                     # pragma: no cover - depends on the box
    BKZ = IntegerMatrix = LLL = None
    HAVE_FPYLLL = False

N = 512
BETA = 80
BOUND = 40
P = None
F = None                      # f coefficients, f[0..N] with f[N] = 1


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------
def load_p(sage_path):
    with open(sage_path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    m = re.search(r"^\s*p\s*=\s*(0x[0-9a-fA-F]+|\d+)", text, re.M)
    if not m:
        raise ValueError("cannot find p in %s" % sage_path)
    return int(m.group(1), 0)


def load_f(sage_path):
    """Parse the (single line) definition f = x^512 + c511*x^511 + ... + c0."""
    with open(sage_path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    m = re.search(r"^\s*f\s*=\s*(.+)$", text, re.M)
    if not m:
        raise ValueError("cannot find f in %s" % sage_path)
    expr = m.group(1).strip()
    coeffs = [0] * (N + 1)
    sign = 1
    token_re = re.compile(r"([+-])|([^+-]+)")
    for mm in token_re.finditer(expr):
        if mm.group(1):
            sign = 1 if mm.group(1) == "+" else -1
            continue
        body = mm.group(2).strip()
        if not body:
            continue
        c = 1
        e = 0
        if "x" in body:
            for part in body.split("*"):
                part = part.strip()
                if part == "x":
                    continue
                if part.startswith("x^"):
                    e = int(part[2:])
                else:
                    c *= int(part)
            if e == 0:                 # plain "c*x"
                e = 1
        else:
            c = int(body)
        coeffs[e] = sign * c
    if coeffs[N] != 1:
        raise ValueError("f is not monic of degree %d" % N)
    return coeffs


def load_samples(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read().strip()
    if text.startswith("output"):
        text = text.split("=", 1)[1].strip()
    samples = ast.literal_eval(text)
    out = []
    for a, b in samples:
        if len(a) != N or len(b) != N:
            raise ValueError("bad sample length")
        out.append((a, b))
    return out


# --------------------------------------------------------------------------
# lattice
# --------------------------------------------------------------------------
def mult_matrix(a):
    """Columns of the multiplication-by-a map in F_p[x]/(f) (power basis)."""
    cols = []
    cur = [x % P for x in a]
    for _ in range(N):
        cols.append(cur)
        top = cur[N - 1]
        nxt = [0] * N
        nxt[0] = (-top * F[0]) % P
        for i in range(1, N):
            nxt[i] = (cur[i - 1] - top * F[i]) % P
        cur = nxt
    return cols


def build_basis(cols, b):
    """Rows of
          [ p*I   0   0 ]
          [ M_a   I   0 ]        with the M_a block stored as its columns,
          [  b    0   K ]        i.e. row j of M_a is cols[j] = a*x^j mod f,
    so that sum_j s_j * row_j = (M_a*s, s, 0) and the Kannan row adds b.
    """
    rows = []
    for i in range(N):
        row = [0] * (2 * N + 1)
        row[i] = P
        rows.append(row)
    for j in range(N):
        row = [0] * (2 * N + 1)
        row[:N] = cols[j]
        row[N + j] = 1
        rows.append(row)
    last = [0] * (2 * N + 1)
    for i in range(N):
        last[i] = b[i] % P
    last[2 * N] = 1
    rows.append(last)
    return rows


def matvec(cols, s):
    """(sum_j s_j * cols[j]) mod p, vectorised with int64."""
    C = np.asarray(cols, dtype=np.int64)         # (N, N)
    v = np.asarray(s, dtype=np.int64)
    return (C.T @ v) % P


def try_row(row, b, cols):
    k = int(row[2 * N])
    if k not in (1, -1):
        return False
    s = [-k * int(v) for v in row[N:2 * N]]
    if max(abs(v) for v in s) > BOUND:
        return False
    prod = matvec(cols, s)
    half = P // 2
    for i in range(N):
        e = (b[i] - int(prod[i])) % P
        if e > half:
            e -= P
        if abs(e) > BOUND:
            return False
    return True


def decide(sample):
    if not HAVE_FPYLLL:
        raise RuntimeError("fpylll is required for LLL/BKZ reduction")
    a, b = sample
    cols = mult_matrix(a)
    A = IntegerMatrix.from_matrix(build_basis(cols, b))
    LLL.reduction(A)
    BKZ.reduction(A, BKZ.Param(block_size=BETA, max_loops=4, flags=BKZ.AUTO_ABORT))
    for i in range(2 * N + 1):
        if try_row([int(v) for v in A[i]], b, cols):
            return 0
    return 1


# --------------------------------------------------------------------------
# driver
# --------------------------------------------------------------------------
def _init(sage_path, beta):
    global P, F, BETA
    P = load_p(sage_path)
    F = load_f(sage_path)
    BETA = beta


def assemble(bits, count):
    bitstr = "".join(str(bits[i]) for i in range(count))
    data = bytes(int(bitstr[i:i + 8], 2) for i in range(0, count, 8))
    return data


def main():
    ap = argparse.ArgumentParser(description="hoRRibleRing solver")
    ap.add_argument("--sage", default="task.sage")
    ap.add_argument("--samples", default="samples.txt")
    ap.add_argument("--bkz", type=int, default=80)
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--start", type=int, default=0)
    ap.add_argument("--end", type=int, default=0)
    ap.add_argument("--out", default="bits.json")
    args = ap.parse_args()

    samples = load_samples(args.samples)
    end = args.end or len(samples)
    todo = list(range(args.start, end))
    bits = {i: None for i in range(len(samples))}

    if not HAVE_FPYLLL:
        print("[-] fpylll is not installed (pip install fpylll); "
              "the 1025-dimensional LLL/BKZ reduction needs it")
        return 1

    if args.jobs <= 1:
        _init(args.sage, args.bkz)
        for i in todo:
            bits[i] = decide(samples[i])
            print("sample %d -> %d" % (i, bits[i]), flush=True)
    else:
        with ProcessPoolExecutor(max_workers=args.jobs, initializer=_init,
                                 initargs=(args.sage, args.bkz)) as pool:
            for i, bit in zip(todo, pool.map(decide, [samples[i] for i in todo])):
                bits[i] = bit
                print("sample %d -> %d" % (i, bit), flush=True)

    Path(args.out).write_text(json.dumps(bits), encoding="utf-8")
    if all(v is not None for v in bits.values()):
        data = assemble(bits, len(samples))
        print("[+] bits   =", "".join(str(bits[i]) for i in range(len(samples))))
        print("[+] flag   =", data.decode("latin-1"))
        print("[*] known-plaintext check (flag{, 0..39):",
              data[:5] == b"flag{", ")")
    else:
        print("[*] partial bit table written to", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
