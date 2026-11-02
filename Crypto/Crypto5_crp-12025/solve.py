#!/usr/bin/env python3
"""crp-12025 solver: partial-factor Coppersmith on a 1248-bit modulus.

N (1248 bits) has the shape 272 + 704 + 272, i.e. it contains a 704-bit
prime factor q.  hint.txt is the 44-byte UTF-8 string

    gylike{魔法仕掛けのファンタジア}

whose integer value H has only 351 significant bits, and q is built as

    q = H * 2**353 + x0,   0 <= x0 < 2**353,

so the top 351 bits of q are known and 353 bits are unknown
(351 + 353 = 704; the shift is 353 and not 352 because the leading byte
0x67 only carries 7 bits).

With beta = 704/1248 = 0.5641 the Coppersmith bound is
X < N^(beta^2) = 2^397.1, comfortably above 2^353, so the standard
univariate small-root lattice works with a tiny dimension:

    rows i = 0..m-1 : N^(m-i) * f(x)^i
    rows k = 0..t-1 : x^k * f(x)^m,     f(x) = x + H*2**353

with the column scaling x -> X*x (column j multiplied by X^j).  After
LLL every short row vanishes modulo q^m at x0, so pairs of rows share
the linear factor (x - x0); gcd of two such polynomials reveals x0 and
q = gcd(N, H*2**353 + x0).

Usage:
    python solve.py --n N.txt --hint hint.txt
    python solve.py --n N.txt --hint hint.txt --ct <TARGET_CT hex>

Requires sympy (Matrix.lll + Poly.gcd).
"""

import argparse
import sys
from math import comb, gcd

from sympy import Matrix, Poly, symbols


def small_root_factor(N, prefix, unknown_bits, m=6, t=6, verbose=True):
    constant = prefix << unknown_bits
    X = 1 << unknown_bits
    dim = m + t

    basis = []
    for i in range(m):
        basis.append([comb(i, j) * constant ** (i - j) * N ** (m - i) * X ** j
                      if j <= i else 0 for j in range(dim)])
    for k in range(t):
        basis.append([comb(m, j - k) * constant ** (m - j + k) * X ** j
                      if k <= j <= m + k else 0 for j in range(dim)])

    if verbose:
        print("[*] lattice dimension %d, X = 2^%d" % (dim, unknown_bits))
    reduced = Matrix(basis).lll()

    x = symbols("x")
    polys = []
    for i in range(dim):
        coeffs = []
        for j in range(dim):
            value, rem = divmod(int(reduced[i, j]), X ** j)
            assert rem == 0, "column scaling was not integral"
            coeffs.append(value)
        polys.append(Poly(sum(coeffs[j] * x ** j for j in range(dim)), x,
                          domain="ZZ"))

    for i in range(dim):
        for j in range(i + 1, dim):
            g = polys[i].gcd(polys[j])
            if g.degree() != 1:
                continue
            a1, a0 = g.all_coeffs()
            num = -a0
            if num % a1 != 0:
                continue
            root = int(num // a1)
            q = gcd(N, constant + root)
            if 1 < q < N:
                return root, q
    return None, None


def main():
    ap = argparse.ArgumentParser(description="crp-12025 Coppersmith solver")
    ap.add_argument("--n", default="N.txt", help="file with the hex modulus")
    ap.add_argument("--hint", default="hint.txt", help="file with the hint bytes")
    ap.add_argument("--factor-bits", type=int, default=704)
    ap.add_argument("--unknown-bits", type=int, default=None,
                    help="number of unknown low bits (default: factor_bits - bitlen(H))")
    ap.add_argument("--m", type=int, default=6)
    ap.add_argument("--t", type=int, default=6)
    ap.add_argument("--ct", default=None, help="TARGET_CT in hex (optional)")
    ap.add_argument("-e", type=int, default=65537)
    args = ap.parse_args()

    with open(args.n, "r", encoding="utf-8") as f:
        N = int(f.read().strip(), 16)
    with open(args.hint, "rb") as f:
        hint = f.read().strip()
    H = int.from_bytes(hint, "big")
    print("[*] N has %d bits, hint is %d bytes / %d bits"
          % (N.bit_length(), len(hint), H.bit_length()))

    unknown_bits = args.unknown_bits
    if unknown_bits is None:
        unknown_bits = args.factor_bits - H.bit_length()
    print("[*] assuming q = H * 2**%d + x0 (q has %d bits)"
          % (unknown_bits, H.bit_length() + unknown_bits))

    root, q = small_root_factor(N, H, unknown_bits, m=args.m, t=args.t)
    if q is None:
        print("[-] LLL basis produced no linear factor; try larger m/t")
        return 1

    print("[+] x0 = %d" % root)
    print("[+] q  = %d" % q)
    print("[*] q has %d bits, N %% q == %d, q >> %d == H -> %s"
          % (q.bit_length(), N % q, unknown_bits, (q >> unknown_bits) == H))
    print("[*] cofactor has %d bits (= %d + %d)"
          % ((N // q).bit_length(), (N // q).bit_length() - 272, 272))

    if args.ct:
        ct = int(args.ct, 16)
        if gcd(args.e, q - 1) != 1:
            print("[-] gcd(e, q-1) != 1, cannot invert modulo q-1")
            return 1
        d = pow(args.e, -1, q - 1)
        m_int = pow(ct, d, q)
        ok = pow(m_int, args.e, N) == ct
        print("[*] full-modulus recheck pow(m, e, N) == TARGET_CT:", ok)
        if not ok:
            print("[-] decryption does not verify")
            return 1
        pt = m_int.to_bytes((m_int.bit_length() + 7) // 8, "big")
        print("[+] plaintext =", pt.decode("latin-1"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
