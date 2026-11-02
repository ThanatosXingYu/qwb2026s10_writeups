"""Directed QTM phase-one pattern databases for checker moves."""

from __future__ import annotations

import pickle
import time
from array import array
from pathlib import Path

from kociemba.pykociemba.coordcube import CoordCube

from hexachord_lab.geometry.custom_flip_tables import load


HERE = Path(__file__).resolve().parent
CACHE = HERE / "directed_phase1_pruning.pkl"
MOVE = (0, 3, 6, 9, 12, 15)


def bfs(coord_move: list[list[int]], slice_move: list[list[int]]) -> bytearray:
    size = len(coord_move) * 495
    dist = bytearray([255]) * size
    dist[0] = 0
    queue = array("I", [0])
    head = 0
    while head < len(queue):
        index = queue[head]
        head += 1
        coord, slice_index = divmod(index, 495)
        new_dist = dist[index] + 1
        row_c = coord_move[coord]
        row_s = slice_move[slice_index]
        for face in range(6):
            nxt = row_c[face] * 495 + row_s[face]
            if dist[nxt] == 255:
                dist[nxt] = new_dist
                queue.append(nxt)
    assert len(queue) == size, (len(queue), size)
    return dist


def build() -> tuple[bytearray, bytearray]:
    custom_flip, _ = load()
    slice_move = [
        [CoordCube.FRtoBR_Move[s * 24][m] // 24 for m in MOVE]
        for s in range(495)
    ]
    twist_move = [[row[m] for m in MOVE] for row in CoordCube.twistMove]
    flip_move = [[row[m] for m in MOVE] for row in custom_flip]
    return bfs(twist_move, slice_move), bfs(flip_move, slice_move)


def load_pruning() -> tuple[bytearray, bytearray]:
    if CACHE.exists():
        with CACHE.open("rb") as f:
            return pickle.load(f)
    tables = build()
    with CACHE.open("wb") as f:
        pickle.dump(tables, f, protocol=pickle.HIGHEST_PROTOCOL)
    return tables


if __name__ == "__main__":
    start = time.monotonic()
    twist, flip = load_pruning()
    print("built", len(twist), len(flip), "max", max(twist), max(flip),
          "seconds", round(time.monotonic() - start, 2))
