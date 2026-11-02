#!/usr/bin/env python3
"""frozen solver.

The service (task.py) samples an NTRU/Falcon key (f, g, F, G) with
f*G - g*F = q, dumps the Falcon LDL tree of the Gram matrix as doubles,
corrupts a few bits of every double, cuts off the first 8*N doubles
(the four spectra) and prints the rest together with the public key
h = g/f and the encrypted flag.

The secret needed for the symmetric key is the negacyclic
autocorrelation

    D = f*adj(f) + g*adj(g)        (integer coefficients, |D| ~ 1e4)

and it is exactly the spectrum G00 = |fh|^2 + |gh|^2 sampled on the
2N-th roots of unity, i.e. D = INTT(G00).  The tree stores only ratios
of neighbouring spectral values (L = t*rho, |t| <= 1) plus the leaf
values, so G00 can be recovered from the (heavily redundant) tree data
by a robust non-linear least squares fit in the log domain with 64
unknowns and 2048 observations (left subtree + mirrored right subtree
q^2/G00).

Usage:
    python solve.py -i transcript.txt
    python solve.py --pubkey pub.json --memory mem.hex --flag ct.hex

Only numpy/scipy are required.
"""

import argparse
import hashlib
import json
import re
import sys

import numpy as np
from scipy.optimize import least_squares


# --------------------------------------------------------------------------
# Falcon tree model (see write-up, section "Falcon树的中间量")
# --------------------------------------------------------------------------
def tree_model(z, want_jac=True):
    """Serialize the Falcon LDL tree of the spectrum exp(z) exactly like
    task.py does (preorder: node Re||Im, then left subtree, then right
    subtree, then the leaves of both subtrees).

    z has n/2 entries; the spectrum is mirrored by conjugation symmetry.
    Returns (values, jacobian) with jacobian of shape (len(values), len(z)).
    """
    n = 2 * len(z)
    idx = np.minimum(np.arange(n), n - 1 - np.arange(n))
    E = np.exp(z[idx])
    J = E[:, None] * np.eye(n // 2)[idx]
    vals, deriv, leaves, dleaf = [], [], [], []

    def rec(E, J):
        m = len(E)
        if m == 1:
            leaves.append(E)
            dleaf.append(J)
            return
        h = m // 2
        a, b = E[:h], E[h:]
        ja, jb = J[:h], J[h:]
        A = (a + b) / 2.0
        JA = (ja + jb) / 2.0
        t = (a - b) / (a + b)
        JT = ((ja - jb) - t[:, None] * (ja + jb)) / (a + b)[:, None]
        rho = np.exp(1j * np.pi * (2 * np.arange(h) + 1) / m)
        L = t * rho
        vals.extend([L.real, L.imag])
        if want_jac:
            deriv.extend([JT * rho.real[:, None], JT * rho.imag[:, None]])
        B = A * (1 - t * t)
        JB = JA * (1 - t * t)[:, None] - 2 * (A * t)[:, None] * JT
        rec(A, JA)
        rec(B, JB)

    rec(E, J)
    values = np.concatenate(vals + leaves)
    if not want_jac:
        return values, None
    return values, np.concatenate(deriv + dleaf)


def split_memory(mem, n):
    """Split the printed double array (4*N*(log2 N) + 4*N doubles) into
    the left tree (spectrum G00) and the right tree (spectrum q^2/G00)."""
    internal = n * (n.bit_length() - 1)
    expect = 2 * internal + 4 * n
    if mem.size != expect:
        raise ValueError("memory has %d doubles, expected %d" % (mem.size, expect))
    left = np.r_[mem[2 * n:2 * n + internal], mem[-2 * n:-n]]
    right = np.r_[mem[2 * n + internal:2 * n + 2 * internal], mem[-n:]]
    return left, right


# --------------------------------------------------------------------------
# Robust least squares (see write-up, section "稳健最小二乘")
# --------------------------------------------------------------------------
def recover(left, right, n=128, q=12289, verbose=True):
    logq2 = 2.0 * np.log(q)

    leaves = left[-n:]
    good = leaves[(leaves > 100) & (leaves < 1e8) & np.isfinite(leaves)]
    if good.size == 0:
        raise ValueError("no usable leaf values")
    scale0 = float(np.median(good))

    obs = np.r_[left, right]
    scales = np.r_[np.full(left.size - n, 0.25), np.full(n, scale0),
                   np.full(right.size - n, 0.25), np.full(n, scale0)]
    limits = np.r_[np.full(left.size - n, 1.01), np.full(n, scale0 * 100.0),
                   np.full(right.size - n, 1.01), np.full(n, scale0 * 100.0)]

    mask = np.isfinite(obs) & (np.abs(obs) <= limits)
    if verbose:
        print("[*] scale0 = %.6g, kept %d/%d observations"
              % (scale0, int(mask.sum()), obs.size))

    z0 = np.full(n // 2, np.log(scale0))
    lo = np.full(n // 2, np.log(scale0) - 8.0)
    hi = np.full(n // 2, np.log(scale0) + 8.0)

    cache = {"z": None, "v": None, "J": None}

    def evaluate(z):
        if cache["z"] is not None and np.array_equal(cache["z"], z):
            return cache["v"], cache["J"]
        v, J = tree_model(z)
        vr, Jr = tree_model(logq2 - z)
        v = np.r_[v, vr]
        J = np.r_[J, -Jr]
        cache.update(z=z.copy(), v=v, J=J)
        return v, J

    def fun(z):
        v, _ = evaluate(z)
        return ((v - obs) / scales)[mask]

    def jac(z):
        _, J = evaluate(z)
        return (J / scales[:, None])[mask]

    z = z0.copy()
    for fs in (1e-2, 1e-4, 1e-6, 1e-8, 1e-10):
        sol = least_squares(fun, z, jac=jac, bounds=(lo, hi), loss="soft_l1",
                            f_scale=fs, max_nfev=150, xtol=1e-14, ftol=1e-14,
                            gtol=1e-14)
        z = sol.x
        if verbose:
            print("[*] f_scale=%.0e  cost=%.6e  optimality=%.3e  nfev=%d"
                  % (fs, sol.cost, sol.optimality, sol.nfev))
    return z


def spectrum_to_D(z, n=128):
    idx = np.minimum(np.arange(n), n - 1 - np.arange(n))
    spec = np.exp(z[idx])
    # G00 is sampled at zeta_j = exp(i*pi*(2j+1)/n); the extra
    # exp(-i*pi*k/n) removes the half-grid offset of the 2n-th roots.
    raw = np.fft.fft(spec) / n * np.exp(-1j * np.pi * np.arange(n) / n)
    return raw


# --------------------------------------------------------------------------
# From D to the flag
# --------------------------------------------------------------------------
def keystream(key, length):
    out = b""
    ctr = 0
    while len(out) < length:
        out += hashlib.sha256(key + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return out[:length]


def decrypt(D, ct):
    canon = ",".join(str(int(c)) for c in D).encode()
    fk = hashlib.sha256(b"frozen:" + canon).digest()
    ks = keystream(fk, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


def parse_transcript(text):
    pub, mem, ct = None, None, None
    m = re.search(r"pubkey\s*=\s*(\{.*\})", text)
    if m:
        pub = json.loads(m.group(1))
    m = re.search(r"memory\s*=\s*([0-9a-fA-F]+)", text)
    if m:
        mem = m.group(1)
    m = re.search(r"flag\s*=\s*([0-9a-fA-F]+)", text)
    if m:
        ct = m.group(1)
    if mem is None or ct is None:
        raise ValueError("could not find 'memory =' / 'flag =' lines")
    return pub, mem, ct


def main():
    ap = argparse.ArgumentParser(description="frozen solver")
    ap.add_argument("-i", "--input", help="file with the service output "
                    "(lines 'pubkey = ...', 'memory = ...', 'flag = ...')")
    ap.add_argument("--pubkey", help="pubkey JSON (optional, overrides -i)")
    ap.add_argument("--memory", help="memory hex string (optional)")
    ap.add_argument("--flag", help="ciphertext hex string (optional)")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    pub, memhex, cthex = None, None, None
    if args.input:
        with open(args.input, "r", encoding="utf-8") as f:
            pub, memhex, cthex = parse_transcript(f.read())
    if args.pubkey:
        pub = json.loads(args.pubkey)
    if args.memory:
        memhex = args.memory
    if args.flag:
        cthex = args.flag
    if memhex is None or cthex is None:
        ap.error("need -i transcript, or --memory and --flag")

    n = int(pub["N"]) if pub else 128
    q = int(pub["q"]) if pub else 12289
    mem = np.frombuffer(bytes.fromhex(memhex), dtype="<f8")
    ct = bytes.fromhex(cthex)

    left, right = split_memory(mem, n)
    z = recover(left, right, n=n, q=q, verbose=not args.quiet)
    raw = spectrum_to_D(z, n)

    err = np.max(np.abs(raw.real - np.rint(raw.real)))
    imerr = np.max(np.abs(raw.imag))
    if not args.quiet:
        print("[*] max |raw - rint| = %.3e, max |imag| = %.3e" % (err, imerr))
    if err > 0.05 or imerr > 0.05:
        print("[-] rounding residual too large, refusing to decrypt")
        return 1

    D = np.rint(raw.real).astype(np.int64)
    # D = f*adj(f) + g*adj(g) is self-adjoint: D[0] free, D[n/2] = 0,
    # D[i] = -D[n-i] otherwise.
    ok = D[n // 2] == 0 and all(int(D[i]) == -int(D[n - i]) for i in range(1, n))
    if not args.quiet:
        print("[*] self-adjoint check:", ok)
        print("[*] D[0] = %d, max|D| = %d" % (D[0], int(np.max(np.abs(D)))))
    if not ok:
        print("[-] recovered D violates the self-adjoint symmetry")
        return 1

    pt = decrypt(D, ct)
    print("[+] flag =", pt.decode("latin-1"))
    if pt.startswith(b"flag{") or b"flag{" in pt:
        print("[+] plaintext looks like a flag")
    return 0


if __name__ == "__main__":
    sys.exit(main())
