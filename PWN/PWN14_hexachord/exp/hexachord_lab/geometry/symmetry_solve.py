"""Retry a directed checker solve under model-preserving cube rotations."""

from __future__ import annotations

import time

from hexachord_lab.geometry.checker_model import FACES, State
from hexachord_lab.geometry.cube_rotations import all_symmetries
from kociemba.pykociemba.facecube import FaceCube
from kociemba.pykociemba.cubiecube import CubieCube
from hexachord_lab.geometry.search_checker_qtm import checker_cube


ROTATIONS = tuple(all_symmetries()[i] for i in (2, 4, 12, 18))
REFLECTIONS = tuple(all_symmetries()[i] for i in (24, 30, 38, 40))


def transform(state: State, rotation) -> State:
    cube = FaceCube(rotation.facelets(
        checker_cube(state).toFaceCube().to_String())).toCubieCube()
    return State(bytes(cube.cp), bytes((1, 3, 2)[x] for x in cube.co),
                 bytes(cube.ep), bytes(x + 1 for x in cube.eo))


def inverse(state: State) -> State:
    cube = CubieCube()
    checker_cube(state).invCubieCube(cube)
    return State(bytes(cube.cp), bytes((1, 3, 2)[x] for x in cube.co),
                 bytes(cube.ep), bytes(x + 1 for x in cube.eo))


def solve_reflections(target_hex: str, reusable, timeout_each: float = 10):
    target = State.from_hex(target_hex)
    inv = inverse(target)
    for i, reflection in enumerate(REFLECTIONS):
        start = time.monotonic()
        reflected_inverse = transform(inv, reflection)
        formula = reusable.solve(reflected_inverse.hex(), timeout_each)
        if formula is not None:
            original = ''.join(reflection.inverse_face(c)
                               for c in reversed(formula))
            assert len(original) <= reusable.budget
            assert State().play(original) == target
            return original, i + 4, time.monotonic() - start
    return None


def solve(target_hex: str, reusable, timeout_each: float = 10,
          include_reflections: bool = True):
    target = State.from_hex(target_hex)
    for i, rotation in enumerate(ROTATIONS):
        start = time.monotonic()
        rotated = transform(target, rotation)
        formula = reusable.solve(rotated.hex(), timeout_each)
        if formula is not None:
            original = ''.join(rotation.inverse_face(c) for c in formula)
            assert len(original) <= reusable.budget
            assert State().play(original) == target
            return original, i, time.monotonic() - start
    if include_reflections:
        return solve_reflections(target_hex, reusable, timeout_each)
    return None


if __name__ == '__main__':
    import sys
    from bidir_reuse import ReusableSolver
    reusable = ReusableSolver(10, 9)
    reusable.prepare()
    for target in sys.argv[1:]:
        print(target, solve(target, reusable), flush=True)
