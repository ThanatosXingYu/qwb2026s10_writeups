"""Build the checker-specific Kociemba edge-flip move and pruning tables."""

from __future__ import annotations

import pickle
from array import array
from pathlib import Path

from kociemba.pykociemba.coordcube import CoordCube
from kociemba.pykociemba.cubiecube import CubieCube, moveCube


HERE = Path(__file__).resolve().parent
CACHE = HERE / "custom_flip_tables.pkl"


def build() -> tuple[list[list[int]], bytearray]:
    custom = list(moveCube)
    f = moveCube[2]
    custom[2] = CubieCube(cp=f.cp[:], co=f.co[:], ep=f.ep[:], eo=[0] * 12)

    move = [[0] * 18 for _ in range(2048)]
    cube = CubieCube()
    for flip in range(2048):
        cube.setFlip(flip)
        for face in range(6):
            for power in range(3):
                cube.edgeMultiply(custom[face])
                move[flip][3 * face + power] = cube.getFlip()
            cube.edgeMultiply(custom[face])

    slice_move = [
        [CoordCube.FRtoBR_Move[slice_index * 24][m] // 24 for m in range(18)]
        for slice_index in range(495)
    ]
    size = 2048 * 495
    dist = bytearray([255]) * size
    dist[0] = 0
    queue = array("I", [0])
    head = 0
    while head < len(queue):
        coord = queue[head]
        head += 1
        flip, slice_index = divmod(coord, 495)
        next_depth = dist[coord] + 1
        row_f = move[flip]
        row_s = slice_move[slice_index]
        for m in range(18):
            nxt = 495 * row_f[m] + row_s[m]
            if dist[nxt] == 255:
                dist[nxt] = next_depth
                queue.append(nxt)
    assert len(queue) == size, (len(queue), size)
    packed = bytearray(size // 2)
    for i in range(0, size, 2):
        packed[i // 2] = dist[i] | (dist[i + 1] << 4)
    return move, packed


def load() -> tuple[list[list[int]], bytearray]:
    if CACHE.exists():
        with CACHE.open("rb") as f:
            return pickle.load(f)
    tables = build()
    with CACHE.open("wb") as f:
        pickle.dump(tables, f, protocol=pickle.HIGHEST_PROTOCOL)
    return tables


if __name__ == "__main__":
    import time
    start = time.monotonic()
    move, pruning = load()
    print("built", len(move), len(pruning), "seconds", round(time.monotonic() - start, 2))
