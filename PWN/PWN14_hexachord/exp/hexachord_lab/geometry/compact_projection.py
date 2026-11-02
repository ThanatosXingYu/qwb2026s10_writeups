"""Memory-efficient phase-one projection BFS with Numba open addressing.

The 11-deep solved-side tree stores ~50 million nodes in about 1 GiB.  Node
indices encode parents in 29 bits, allowing a deeper meet than Python dicts.
"""

from __future__ import annotations

import time

import numpy as np
from numba import njit

from hexachord_lab.geometry.checker_model import State
from hexachord_lab.geometry.directed_solve import Solver
from kociemba.pykociemba.coordcube import CoordCube


@njit(cache=True)
def bucket(key: int, mask: int) -> int:
    return (key * 2654435761) & mask


@njit(cache=True)
def lookup(table: np.ndarray, keys: np.ndarray, key: int) -> int:
    mask = len(table) - 1
    pos = bucket(key, mask)
    while True:
        entry = int(table[pos])
        if entry == 0:
            return -1
        idx = entry - 1
        if int(keys[idx]) == key:
            return idx
        pos = (pos + 1) & mask


@njit(cache=True)
def build(keys: np.ndarray, parents: np.ndarray,
          alt_parents: np.ndarray, table: np.ndarray,
          twist_move: np.ndarray, flip_move: np.ndarray,
          slice_move: np.ndarray, root_key: int, depth: int,
          reversed_moves: bool,
          other_keys: np.ndarray, other_table: np.ndarray,
          meet_self: np.ndarray, meet_other: np.ndarray) -> tuple[int, int]:
    keys[0] = root_key
    parents[0] = np.uint32(0xffffffff)
    if len(alt_parents):
        alt_parents[0] = np.uint32(0xffffffff)
    table[bucket(root_key, len(table)-1)] = 1
    count = 1
    begin = 0
    meets = 0
    for level in range(depth + 1):
        end = count
        for idx in range(begin, end):
            key = int(keys[idx])
            if len(other_table):
                other = lookup(other_table, other_keys, key)
                if other >= 0:
                    if meets < len(meet_self):
                        meet_self[meets] = idx
                        meet_other[meets] = other
                        meets += 1
            if level == depth:
                continue
            s = key % 495
            q = key // 495
            f = q % 2048
            t = q // 2048
            for face in range(6):
                m = face * 3 + (2 if reversed_moves else 0)
                nkey = (int(twist_move[t, m]) * 2048
                        + int(flip_move[f, m])) * 495 + int(slice_move[s, face])
                mask = len(table) - 1
                pos = bucket(nkey, mask)
                while True:
                    entry = int(table[pos])
                    if entry == 0:
                        if count >= len(keys):
                            raise ValueError('node capacity exhausted')
                        keys[count] = nkey
                        parents[count] = (idx << 3) | face
                        if len(alt_parents):
                            alt_parents[count] = np.uint32(0xffffffff)
                        table[pos] = count + 1
                        count += 1
                        break
                    if int(keys[entry-1]) == nkey:
                        existing = entry - 1
                        if (len(alt_parents) and existing >= end and
                            int(alt_parents[existing]) == 0xffffffff and
                            int(parents[existing]) != ((idx << 3) | face)):
                            alt_parents[existing] = (idx << 3) | face
                        break
                    pos = (pos + 1) & mask
        begin = end
    return count, meets


def move_arrays():
    Solver(State(), 31, 1, 1)
    twist = np.asarray(CoordCube.twistMove, dtype=np.uint16)
    flip = np.asarray(CoordCube.flipMove, dtype=np.uint16)
    fr = np.asarray(CoordCube.FRtoBR_Move, dtype=np.uint16)
    slice_plus = np.ascontiguousarray(fr[::24, ::3] // 24, dtype=np.uint16)
    slice_minus = np.ascontiguousarray(fr[::24, 2::3] // 24, dtype=np.uint16)
    return twist, flip, slice_plus, slice_minus


class ProjectionTree:
    def __init__(self, depth: int, node_capacity: int, hash_power: int,
                 alternates: bool = True):
        self.depth = depth
        self.keys = np.empty(node_capacity, dtype=np.uint32)
        self.parents = np.empty(node_capacity, dtype=np.uint32)
        self.alt_parents = (np.empty(node_capacity, dtype=np.uint32)
                            if alternates else np.empty(0, dtype=np.uint32))
        self.table = np.zeros(1 << hash_power, dtype=np.uint32)
        self.count = 0

    def construct(self, root_key: int, moves, reversed_moves: bool,
                  other: 'ProjectionTree | None' = None,
                  meet_capacity: int = 1000000):
        twist, flip, plus, minus = moves
        slice_move = minus if reversed_moves else plus
        if other is None:
            other_keys = np.empty(0, dtype=np.uint32)
            other_table = np.empty(0, dtype=np.uint32)
            meet_self = np.empty(0, dtype=np.uint32)
            meet_other = np.empty(0, dtype=np.uint32)
        else:
            other_keys = other.keys
            other_table = other.table
            meet_self = np.empty(meet_capacity, dtype=np.uint32)
            meet_other = np.empty(meet_capacity, dtype=np.uint32)
        start = time.monotonic()
        count, meet_count = build(self.keys, self.parents, self.alt_parents,
                                  self.table,
                                  twist, flip, slice_move, root_key,
                                  self.depth, reversed_moves,
                                  other_keys, other_table,
                                  meet_self, meet_other)
        self.count = count
        return time.monotonic() - start, meet_self[:meet_count], meet_other[:meet_count]

    def path(self, index: int) -> list[int]:
        result = []
        while index:
            packed = int(self.parents[index])
            result.append(packed & 7)
            index = packed >> 3
        result.reverse()
        return result

    def path_variants(self, index: int, max_paths: int = 4) -> list[list[int]]:
        base = self.path(index)
        if not len(self.alt_parents) or max_paths == 1:
            return [base]
        result = [base]
        seen = {tuple(base)}
        node = index
        suffix: list[int] = []
        while node and len(result) < max_paths:
            alt = int(self.alt_parents[node])
            if alt != 0xffffffff:
                candidate = self.path(alt >> 3) + [alt & 7] + suffix
                key = tuple(candidate)
                if key not in seen:
                    seen.add(key)
                    result.append(candidate)
            primary = int(self.parents[node])
            suffix.insert(0, primary & 7)
            node = primary >> 3
        return result


if __name__ == '__main__':
    import psutil
    import sys
    from search_checker_qtm import checker_cube
    from kociemba.pykociemba.coordcube import CoordCube

    depth = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    moves = move_arrays()
    forward = ProjectionTree(depth, 60000000 if depth == 11 else 12000000,
                             27 if depth == 11 else 25)
    print('constructed', forward.construct(0, moves, False)[0],
          forward.count, 'rss', psutil.Process().memory_info().rss // 1048576,
          flush=True)
    if len(sys.argv) > 2:
        target = State.from_hex(sys.argv[2])
        c = CoordCube(checker_cube(target))
        root = (c.twist * 2048 + c.flip) * 495 + c.FRtoBR // 24
        backward = ProjectionTree(9, 6000000, 24)
        elapsed, a, b = backward.construct(root, moves, True, forward)
        print('backward', elapsed, backward.count, len(a),
              'rss', psutil.Process().memory_info().rss // 1048576, flush=True)
