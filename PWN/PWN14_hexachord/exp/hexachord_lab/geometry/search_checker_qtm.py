"""Sample distinct Kociemba paths for the checker's directed quarter-turn metric."""

from __future__ import annotations

import argparse
import random
import time

from kociemba.pykociemba.coordcube import CoordCube
from kociemba.pykociemba.cubiecube import CubieCube, moveCube
from kociemba.pykociemba.search import Search

from hexachord_lab.geometry.checker_model import FACES, State
from hexachord_lab.geometry.custom_flip_tables import load
from hexachord_lab.geometry.solve_cube import inverse_formula, parse_target, quarter_only


def checker_cube(target: State) -> CubieCube:
    b = bytearray.fromhex(target.hex())
    b[8:16] = bytes(5 - value if value > 1 else value for value in b[8:16])
    return parse_target(b.hex())


def apply_formula(cube: CubieCube, formula: str, moves: list[CubieCube]) -> None:
    for word in formula.split():
        face = FACES.index(word[0])
        count = 2 if word.endswith("2") else 3 if word.endswith("'") else 1
        for _ in range(count):
            cube.multiply(moves[face])


def search(target_hex: str, rounds: int, seed: int) -> None:
    target = State.from_hex(target_hex)
    original = checker_cube(target)
    CoordCube.flipMove, CoordCube.Slice_Flip_Prun = load()
    moves = list(moveCube)
    f = moveCube[2]
    moves[2] = CubieCube(cp=f.cp[:], co=f.co[:], ep=f.ep[:], eo=[0] * 12)
    rng = random.Random(seed)
    start = time.monotonic()
    best = 999
    for trial in range(rounds):
        cube = CubieCube(cp=original.cp[:], co=original.co[:],
                         ep=original.ep[:], eo=original.eo[:])
        suffix = ""
        for _ in range(rng.randrange(0, 9)):
            face = rng.randrange(6)
            count = rng.choice((1, 1, 1, 2, 3))
            suffix += FACES[face] + ("" if count == 1 else "2" if count == 2 else "'") + " "
        apply_formula(cube, suffix, moves)
        result = Search().solution(cube.toFaceCube().to_String(), 31, 0.5, False)
        if result.startswith("Error"):
            continue
        to_target = inverse_formula(suffix + result)
        qtm = quarter_only(to_target)
        if len(qtm) < best:
            assert State().play(qtm) == target
            best = len(qtm)
            print(trial, "best", best, "seconds", round(time.monotonic() - start, 2),
                  "formula", to_target, "residues", qtm, flush=True)
        if best <= 31:
            break


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--rounds", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    search(args.target, args.rounds, args.seed)
