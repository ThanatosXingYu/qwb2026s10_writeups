"""Reusable directed quarter-turn solver for Hexachord checker targets.

Construct the solved-side projection tree once, then solve many target states.
The returned ASCII letters are the exact clockwise move residues required by
the checker.  Call ``prepare()`` before opening a remote connection.
"""

from __future__ import annotations

import argparse
import time
from array import array

from hexachord_lab.geometry.checker_model import FACES, State
from hexachord_lab.geometry.directed_solve import Solver
from kociemba.pykociemba.coordcube import CoordCube


def pack(twist: int, flip: int, slice_index: int) -> int:
    return (twist * 2048 + flip) * 495 + slice_index


def unpack(value: int) -> tuple[int, int, int]:
    q, slice_index = divmod(value, 495)
    twist, flip = divmod(q, 2048)
    return twist, flip, slice_index


def recover(parents: dict[int, tuple[int, int]], node: int) -> list[int]:
    result = []
    while parents[node][0] != -1:
        parent, face = parents[node]
        result.append(face)
        node = parent
    result.reverse()
    return result


class ReusableSolver:
    def __init__(self, forward_depth: int = 9, backward_depth: int = 9,
                 budget: int = 31):
        self.forward_depth = forward_depth
        self.backward_depth = backward_depth
        self.budget = budget
        self.forward: dict[int, tuple[int, int]] | None = None
        self.slice_move = None
        self.slice_inv = None

    def prepare(self) -> None:
        if self.forward is not None:
            return
        # Building Solver also loads the checker's custom flip table.
        Solver(State(), self.budget, 1, 0)
        twist_move = CoordCube.twistMove
        flip_move = CoordCube.flipMove
        fr_move = CoordCube.FRtoBR_Move
        self.slice_move = [
            [fr_move[s * 24][3 * f] // 24 for f in range(6)]
            for s in range(495)
        ]
        self.slice_inv = [
            [fr_move[s * 24][3 * f + 2] // 24 for f in range(6)]
            for s in range(495)
        ]
        forward = {0: (-1, -1)}
        frontier = array("I", [0])
        for _ in range(self.forward_depth):
            nxt = array("I")
            for key in frontier:
                twist, flip, slice_index = unpack(key)
                row_t = twist_move[twist]
                row_f = flip_move[flip]
                row_s = self.slice_move[slice_index]
                for face in range(6):
                    state = pack(row_t[3 * face], row_f[3 * face],
                                 row_s[face])
                    if state not in forward:
                        forward[state] = (key, face)
                        nxt.append(state)
            frontier = nxt
        self.forward = forward

    def solve(self, target_hex: str, timeout: float = 30) -> str | None:
        self.prepare()
        assert self.forward is not None
        assert self.slice_inv is not None
        target = State.from_hex(target_hex)
        solver = Solver(target, self.budget, timeout,
                        self.forward_depth + self.backward_depth)
        twist_move = CoordCube.twistMove
        flip_move = CoordCube.flipMove
        fr_move = CoordCube.FRtoBR_Move
        c = solver.state
        start_key = pack(c.twist, c.flip, c.FRtoBR // 24)
        backward: dict[int, tuple[int, int]] = {start_key: (-1, -1)}
        frontier = array("I", [start_key])
        for depth in range(self.backward_depth + 1):
            nxt = array("I")
            for key in frontier:
                if key in self.forward:
                    path = recover(backward, key) + list(
                        reversed(recover(self.forward, key)))
                    if len(path) <= self.budget:
                        twist, flip, fr = c.twist, c.flip, c.FRtoBR
                        cp, urul, ubdf, parity = (
                            c.URFtoDLF, c.URtoUL, c.UBtoDF, c.parity)
                        for face in path:
                            m = 3 * face + 2
                            twist = twist_move[twist][m]
                            flip = flip_move[flip][m]
                            fr = fr_move[fr][m]
                            cp = CoordCube.URFtoDLF_Move[cp][m]
                            urul = CoordCube.URtoUL_Move[urul][m]
                            ubdf = CoordCube.UBtoDF_Move[ubdf][m]
                            parity = CoordCube.parityMove[parity][m]
                        assert twist == flip == 0 and fr < 24
                        if urul < 336 and ubdf < 336:
                            ep = CoordCube.MergeURtoULandUBtoDF[urul][ubdf]
                            if len(path) + solver.h2(cp, ep, fr, parity) <= self.budget:
                                solver.phase1_path = [3 * face + 2 for face in path]
                                solver.phase2_path = []
                                try:
                                    found = solver.search_phase2(
                                        cp, ep, fr, parity, len(path), -1)
                                except TimeoutError:
                                    return None
                                if found:
                                    assert solver.result is not None
                                    residues = "".join(
                                        FACES[m // 3] * (3 - m % 3)
                                        for m in reversed(solver.result))
                                    assert len(residues) <= self.budget
                                    assert State().play(residues) == target
                                    return residues
                if depth == self.backward_depth:
                    continue
                twist, flip, slice_index = unpack(key)
                row_t = twist_move[twist]
                row_f = flip_move[flip]
                row_s = self.slice_inv[slice_index]
                for face in range(6):
                    m = 3 * face + 2
                    state = pack(row_t[m], row_f[m], row_s[face])
                    if state not in backward:
                        backward[state] = (key, face)
                        nxt.append(state)
            frontier = nxt
            if time.monotonic() > solver.deadline:
                return None
        return None


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("targets", nargs="+")
    p.add_argument("--forward-depth", type=int, default=9)
    p.add_argument("--backward-depth", type=int, default=9)
    p.add_argument("--timeout", type=float, default=30)
    args = p.parse_args()
    start = time.monotonic()
    reusable = ReusableSolver(args.forward_depth, args.backward_depth)
    reusable.prepare()
    print("prepared", len(reusable.forward or ()),
          round(time.monotonic() - start, 3), flush=True)
    for target_hex in args.targets:
        t0 = time.monotonic()
        result = reusable.solve(target_hex, args.timeout)
        print(target_hex, result, len(result) if result else 0,
              round(time.monotonic() - t0, 3), flush=True)
