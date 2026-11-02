"""Directed corner-permutation lower bound for Hexachord quarter turns."""

from __future__ import annotations

import pickle
from array import array
from pathlib import Path

from kociemba.pykociemba.coordcube import CoordCube


CACHE = Path(__file__).with_suffix(".pkl")
MOVE = (0, 3, 6, 9, 12, 15)


def load_pruning() -> bytearray:
    if CACHE.exists():
        with CACHE.open("rb") as f:
            return pickle.load(f)
    dist = bytearray([255]) * (20160 * 2)
    dist[0] = 0
    queue = array("I", [0])
    head = 0
    while head < len(queue):
        state = queue[head]
        head += 1
        coord, parity = divmod(state, 2)
        nd = dist[state] + 1
        for m in MOVE:
            nxt = CoordCube.URFtoDLF_Move[coord][m] * 2 + CoordCube.parityMove[parity][m]
            if dist[nxt] == 255:
                dist[nxt] = nd
                queue.append(nxt)
    assert len(queue) == len(dist)
    with CACHE.open("wb") as f:
        pickle.dump(dist, f, protocol=pickle.HIGHEST_PROTOCOL)
    return dist


if __name__ == "__main__":
    p = load_pruning()
    print("built", len(p), "max", max(p))
