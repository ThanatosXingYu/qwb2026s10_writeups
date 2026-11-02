"""11+9 checker search using compressed Numba projection trees.

The solved-side table is reusable across chapters.  Unlike the Python dict
version, 50.7 million projected states fit in roughly 1 GiB and build in a
few seconds.  Phase two still uses the exact custom checker tables.
"""

from __future__ import annotations

import time

import numpy as np

from hexachord_lab.geometry.checker_model import FACES, State
from hexachord_lab.geometry.compact_candidate_eval import evaluate_base, arrays
from hexachord_lab.geometry.compact_projection import ProjectionTree, move_arrays
from hexachord_lab.geometry.directed_solve import Solver
from kociemba.pykociemba.coordcube import CoordCube


class CompactSolver:
    def __init__(self, forward_depth: int = 11, backward_depth: int = 9,
                 budget: int = 31):
        self.forward_depth = forward_depth
        self.backward_depth = backward_depth
        self.budget = budget
        self.moves = None
        self.forward = None

    def _jit_candidates(self, solver, backward, back_indices, forward_indices):
        c = solver.state
        capacity = 2000000 if len(back_indices) > 10000000 else 1000000
        output = arrays(capacity)
        n = evaluate_base(
            back_indices, forward_indices,
            backward.parents, self.forward.parents,
            c.URFtoDLF, c.URtoUL, c.UBtoDF, c.FRtoBR, c.parity,
            np.asarray(CoordCube.URFtoDLF_Move, dtype=np.uint16),
            np.asarray(CoordCube.URtoUL_Move, dtype=np.uint16),
            np.asarray(CoordCube.UBtoDF_Move, dtype=np.uint16),
            np.asarray(CoordCube.FRtoBR_Move, dtype=np.uint16),
            np.asarray(CoordCube.parityMove, dtype=np.uint8),
            np.asarray(CoordCube.MergeURtoULandUBtoDF, dtype=np.int16),
            np.frombuffer(solver.cp_phase2_prun, dtype=np.uint8),
            np.frombuffer(solver.ep_phase2_prun, dtype=np.uint8),
            self.budget, *output,
        )
        candidates = {}
        paths, costs, h2s, cps, eps, frs, parities = output
        for i in range(n):
            cost = int(costs[i])
            cp, ep, fr, parity = (int(cps[i]), int(eps[i]),
                                  int(frs[i]), int(parities[i]))
            full_key = (cp, ep, fr, parity)
            old = candidates.get(full_key)
            if old is None or cost < old[0]:
                path = [int(v) for v in paths[i, :cost]]
                candidates[full_key] = (
                    cost, int(h2s[i]), path, cp, ep, fr, parity)
        return candidates

    def prepare(self):
        if self.forward is not None:
            return
        self.moves = move_arrays()
        size = (240000000 if self.forward_depth == 12 else
                60000000 if self.forward_depth == 11 else 12000000)
        power = (29 if self.forward_depth == 12 else
                 27 if self.forward_depth == 11 else 25)
        self.forward = ProjectionTree(self.forward_depth, size, power,
                                      alternates=self.forward_depth < 12)
        self.forward.construct(0, self.moves, False)

    def solve(self, target_hex: str, timeout: float = 30,
              forward_paths: int = 1,
              backward_paths: int = 1) -> str | None:
        if self.backward_depth == 10:
            # Most targets are solved at depth nine.  Processing millions of
            # depth-ten meets first delays them and can exhaust meet storage.
            start = time.monotonic()
            self.backward_depth = 9
            try:
                first = self.solve(target_hex, min(timeout, 10),
                                   forward_paths, backward_paths)
            finally:
                self.backward_depth = 10
            if first is not None:
                return first
            timeout -= time.monotonic() - start
            if timeout <= 0:
                return None
        self.prepare()
        assert self.forward is not None and self.moves is not None
        target = State.from_hex(target_hex)
        solver = Solver(target, self.budget, timeout,
                        self.forward_depth + self.backward_depth)
        c = solver.state
        key = (c.twist * 2048 + c.flip) * 495 + c.FRtoBR // 24
        backward = ProjectionTree(
            self.backward_depth,
            30000000 if self.backward_depth == 10 else 6000000,
            26 if self.backward_depth == 10 else 24)
        _, back_indices, forward_indices = backward.construct(
            key, self.moves, True, self.forward,
            meet_capacity=(20000000 if self.forward_depth == 12 and
                           self.backward_depth == 10 else 5000000))
        tw = CoordCube.twistMove
        fl = CoordCube.flipMove
        fr_move = CoordCube.FRtoBR_Move
        cp_move = CoordCube.URFtoDLF_Move
        urul_move = CoordCube.URtoUL_Move
        ubdf_move = CoordCube.UBtoDF_Move
        parity_move = CoordCube.parityMove
        if forward_paths == backward_paths == 1:
            candidates = self._jit_candidates(
                solver, backward, back_indices, forward_indices)
            pair_iter = ()
        else:
            candidates = {}
            pair_iter = zip(back_indices, forward_indices)
        for bidx, fidx in pair_iter:
            back_paths = backward.path_variants(int(bidx), backward_paths)
            forward_paths_here = self.forward.path_variants(int(fidx), forward_paths)
            for back_path in back_paths:
                for forward_path in forward_paths_here:
                    path = back_path + list(reversed(forward_path))
                    cost = len(path)
                    if cost > self.budget:
                        continue
                    twist, flip, fr = c.twist, c.flip, c.FRtoBR
                    cp, urul, ubdf, parity = (
                        c.URFtoDLF, c.URtoUL, c.UBtoDF, c.parity)
                    for face in path:
                        m = face * 3 + 2
                        twist = tw[twist][m]
                        flip = fl[flip][m]
                        fr = fr_move[fr][m]
                        cp = cp_move[cp][m]
                        urul = urul_move[urul][m]
                        ubdf = ubdf_move[ubdf][m]
                        parity = parity_move[parity][m]
                    assert twist == flip == 0 and fr < 24
                    if urul >= 336 or ubdf >= 336:
                        continue
                    ep = CoordCube.MergeURtoULandUBtoDF[urul][ubdf]
                    h2 = solver.h2(cp, ep, fr, parity)
                    if cost + h2 > self.budget:
                        continue
                    full_key = (cp, ep, fr, parity)
                    old = candidates.get(full_key)
                    if old is None or cost < old[0]:
                        candidates[full_key] = (cost, h2, path, cp, ep, fr, parity)
            if time.monotonic() > solver.deadline:
                return None
        del backward
        for cost, h2, path, cp, ep, fr, parity in sorted(
            candidates.values(), key=lambda x: (x[0] + x[1], x[0])):
            solver.phase1_path = [3 * face + 2 for face in path]
            solver.phase2_path = []
            try:
                found = solver.search_phase2(cp, ep, fr, parity, cost, -1)
            except TimeoutError:
                return None
            if found:
                assert solver.result is not None
                residues = ''.join(FACES[m // 3] * (3 - m % 3)
                                   for m in reversed(solver.result))
                assert len(residues) <= self.budget
                assert State().play(residues) == target
                return residues
        return None


if __name__ == '__main__':
    import psutil
    import sys
    solver = CompactSolver()
    start = time.monotonic()
    solver.prepare()
    print('prepared', round(time.monotonic() - start, 2),
          solver.forward.count if solver.forward else -1,
          'rss', psutil.Process().memory_info().rss // 1048576,
          flush=True)
    for target in sys.argv[1:]:
        start = time.monotonic()
        answer = solver.solve(target, 30)
        print(target, answer, round(time.monotonic() - start, 2),
              'rss', psutil.Process().memory_info().rss // 1048576,
              flush=True)
