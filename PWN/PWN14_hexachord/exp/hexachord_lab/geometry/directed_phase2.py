"""Directed QTM phase-two pattern databases for checker moves.

The search runs target->solved using counterclockwise face turns.  PDBs are
built in the reverse graph: U/D clockwise cost 1 and side-face half turns
cost 2.  Side-face half turns are involutions.
"""

from __future__ import annotations

import pickle
import time
from array import array
from pathlib import Path

from kociemba.pykociemba.coordcube import CoordCube


HERE = Path(__file__).resolve().parent
CACHE = HERE / "directed_phase2_pruning.pkl"
MOVES = (0, 9, 4, 7, 13, 16)  # U, D, R2, F2, L2, B2
COSTS = (1, 1, 2, 2, 2, 2)
N = 20160 * 24 * 2


def build_one(perm_move: list[list[int]]) -> bytearray:
    perm_rows = [[row[m] for m in MOVES] for row in perm_move]
    slice_rows = [[CoordCube.FRtoBR_Move[s][m] for m in MOVES]
                  for s in range(24)]
    parity_rows = [[CoordCube.parityMove[p][m] for m in MOVES]
                   for p in range(2)]
    dist = bytearray([255]) * N
    dist[0] = 0
    buckets = [array("I") for _ in range(100)]
    heads = [0] * 100
    buckets[0].append(0)
    count = 1
    depth = 0
    while count < N:
        if heads[depth] == len(buckets[depth]):
            depth += 1
            if depth >= len(buckets):
                raise RuntimeError(("unreached", count))
            continue
        index = buckets[depth][heads[depth]]
        heads[depth] += 1
        if dist[index] != depth:
            continue
        tmp, parity = divmod(index, 2)
        perm, slice_index = divmod(tmp, 24)
        pp = perm_rows[perm]
        ss = slice_rows[slice_index]
        qq = parity_rows[parity]
        for i in range(6):
            nxt = (pp[i] * 24 + ss[i]) * 2 + qq[i]
            nd = depth + COSTS[i]
            if nd < dist[nxt]:
                if dist[nxt] == 255:
                    count += 1
                dist[nxt] = nd
                buckets[nd].append(nxt)
    return dist


def build() -> tuple[bytearray, bytearray]:
    return (build_one(CoordCube.URFtoDLF_Move),
            build_one(CoordCube.URtoDF_Move))


def load_pruning() -> tuple[bytearray, bytearray]:
    if CACHE.exists():
        with CACHE.open("rb") as f:
            return pickle.load(f)
    result = build()
    with CACHE.open("wb") as f:
        pickle.dump(result, f, protocol=pickle.HIGHEST_PROTOCOL)
    return result


if __name__ == "__main__":
    start = time.monotonic()
    a, b = load_pruning()
    print("built", len(a), len(b), "max", max(a), max(b),
          "seconds", round(time.monotonic() - start, 2))
