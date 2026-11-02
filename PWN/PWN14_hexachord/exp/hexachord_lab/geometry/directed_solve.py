"""Two-phase directed quarter-turn search for a Hexachord checker target."""

from __future__ import annotations

import argparse
import time

from hexachord_lab.geometry.checker_model import FACES, State
from hexachord_lab.geometry.custom_flip_tables import load
from hexachord_lab.geometry.directed_cp_pruning import load_pruning as load_cp
from hexachord_lab.geometry.directed_phase2 import load_pruning as load_phase2
from hexachord_lab.geometry.directed_pruning import load_pruning as load_phase1
from kociemba.pykociemba.coordcube import CoordCube
from hexachord_lab.geometry.search_checker_qtm import checker_cube
from hexachord_lab.geometry.solve_cube import quarter_only


PHASE1_MOVES = tuple(3 * face + power for face in range(6) for power in (2, 1, 0))
PHASE2_MOVES = (2, 11, 1, 10, 4, 7, 13, 16, 0, 9)
COST = tuple((3, 2, 1)[m % 3] for m in range(18))


def compatible(last_face: int, face: int) -> bool:
    return last_face != face and last_face - 3 != face


class Solver:
    def __init__(self, target: State, budget: int, timeout: float, max_phase1: int):
        self.target = target
        self.budget = budget
        self.deadline = time.monotonic() + timeout
        self.max_phase1 = max_phase1
        self.twist_prun, self.flip_prun = load_phase1()
        self.cp_prun = load_cp()
        self.cp_phase2_prun, self.ep_phase2_prun = load_phase2()
        CoordCube.flipMove, CoordCube.Slice_Flip_Prun = load()
        self.state = CoordCube(checker_cube(target))
        self.phase1_path: list[int] = []
        self.phase2_path: list[int] = []
        self.result: list[int] | None = None
        self.nodes1 = 0
        self.nodes2 = 0
        self.phase2_calls = 0

    def h1(self, twist: int, flip: int, fr: int, cp: int, parity: int) -> int:
        s = fr // 24
        return max(self.twist_prun[twist * 495 + s],
                   self.flip_prun[flip * 495 + s],
                   self.cp_prun[cp * 2 + parity])

    def h2(self, cp: int, ep: int, fr: int, parity: int) -> int:
        index_cp = (cp * 24 + fr) * 2 + parity
        index_ep = (ep * 24 + fr) * 2 + parity
        return max(self.cp_phase2_prun[index_cp],
                   self.ep_phase2_prun[index_ep])

    def search_phase2(self, cp: int, ep: int, fr: int, parity: int,
                      spent: int, last_face: int) -> bool:
        self.nodes2 += 1
        if self.nodes2 % 100000 == 0 and time.monotonic() > self.deadline:
            raise TimeoutError
        h = self.h2(cp, ep, fr, parity)
        if spent + h > self.budget:
            return False
        if cp == 0 and ep == 0 and fr == 0 and parity == 0:
            self.result = self.phase1_path + self.phase2_path
            return True
        candidates = []
        for m in PHASE2_MOVES:
            face = m // 3
            cost = COST[m]
            if spent + cost > self.budget or not compatible(last_face, face):
                continue
            ncp = CoordCube.URFtoDLF_Move[cp][m]
            nep = CoordCube.URtoDF_Move[ep][m]
            nfr = CoordCube.FRtoBR_Move[fr][m]
            np = CoordCube.parityMove[parity][m]
            nh = self.h2(ncp, nep, nfr, np)
            if spent + cost + nh <= self.budget:
                candidates.append((cost + nh, cost, m, ncp, nep, nfr, np))
        candidates.sort()
        for _, cost, m, ncp, nep, nfr, np in candidates:
            self.phase2_path.append(m)
            if self.search_phase2(ncp, nep, nfr, np, spent + cost, m // 3):
                return True
            self.phase2_path.pop()
        return False

    def search_phase1(self, twist: int, flip: int, fr: int, cp: int,
                      urul: int, ubdf: int, parity: int, spent: int,
                      last_face: int) -> bool:
        self.nodes1 += 1
        if self.nodes1 % 100000 == 0 and time.monotonic() > self.deadline:
            raise TimeoutError
        h = self.h1(twist, flip, fr, cp, parity)
        if spent + h > self.budget:
            return False
        if twist == 0 and flip == 0 and fr < 24:
            self.phase2_calls += 1
            if urul < 336 and ubdf < 336:
                ep = CoordCube.MergeURtoULandUBtoDF[urul][ubdf]
                if self.search_phase2(cp, ep, fr, parity, spent, last_face):
                    return True
        if spent >= self.max_phase1:
            return False
        candidates = []
        for m in PHASE1_MOVES:
            face = m // 3
            cost = COST[m]
            if spent + cost > self.budget or not compatible(last_face, face):
                continue
            nt = CoordCube.twistMove[twist][m]
            nf = CoordCube.flipMove[flip][m]
            nr = CoordCube.FRtoBR_Move[fr][m]
            nc = CoordCube.URFtoDLF_Move[cp][m]
            np = CoordCube.parityMove[parity][m]
            nh = self.h1(nt, nf, nr, nc, np)
            if spent + cost + nh <= self.budget:
                candidates.append((cost + nh, cost, m, nt, nf, nr, nc, np))
        candidates.sort()
        for _, cost, m, nt, nf, nr, nc, np in candidates:
            nu = CoordCube.URtoUL_Move[urul][m]
            nb = CoordCube.UBtoDF_Move[ubdf][m]
            self.phase1_path.append(m)
            if self.search_phase1(nt, nf, nr, nc, nu, nb, np,
                                  spent + cost, m // 3):
                return True
            self.phase1_path.pop()
        return False

    def solve(self) -> str | None:
        c = self.state
        try:
            found = self.search_phase1(c.twist, c.flip, c.FRtoBR,
                                       c.URFtoDLF, c.URtoUL, c.UBtoDF,
                                       c.parity, 0, -1)
        except TimeoutError:
            print("timeout", self.nodes1, self.nodes2,
                  self.phase2_calls, flush=True)
            return None
        if not found:
            print("exhausted", self.nodes1, self.nodes2,
                  self.phase2_calls, flush=True)
            return None
        assert self.result is not None
        reverse_words = [FACES[m // 3] + ("" if m % 3 == 0 else "2" if m % 3 == 1 else "'")
                         for m in self.result]
        to_target_words = []
        for word in reversed(reverse_words):
            if word.endswith("2"):
                to_target_words.append(word)
            elif word.endswith("'"):
                to_target_words.append(word[0])
            else:
                to_target_words.append(word + "'")
        formula = " ".join(to_target_words)
        residues = quarter_only(formula)
        assert len(residues) <= self.budget
        assert State().play(residues) == self.target
        print("FOUND", len(residues), "nodes", self.nodes1, self.nodes2,
              "phase2_calls", self.phase2_calls, flush=True)
        print("formula", formula, flush=True)
        print("residues", residues, flush=True)
        return residues


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("--budget", type=int, default=31)
    p.add_argument("--timeout", type=float, default=120)
    p.add_argument("--max-phase1", type=int, default=18)
    args = p.parse_args()
    start = time.monotonic()
    solver = Solver(State.from_hex(args.target), args.budget,
                    args.timeout, args.max_phase1)
    solver.solve()
    print("seconds", round(time.monotonic() - start, 2), flush=True)
