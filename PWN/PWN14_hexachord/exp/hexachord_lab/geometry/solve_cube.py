"""Solve a Hexachord 40-byte cubie target using Kociemba's cube convention.

The target is cp[8], co[8] (one based), ep[12], eo[12] (one based).
Print the face moves from a solved cube to the target, plus its inverse.
"""

from __future__ import annotations

import argparse
import re

import kociemba
from kociemba.pykociemba.cubiecube import CubieCube, moveCube


FACES = "URFDLB"


def parse_target(raw: str) -> CubieCube:
    compact = re.sub(r"\s+", "", raw)
    if len(compact) != 80 or not re.fullmatch(r"[0-9a-fA-F]{80}", compact):
        raise ValueError("target must be exactly 40 hex-encoded bytes")
    values = list(bytes.fromhex(compact))
    cube = CubieCube(
        cp=values[:8],
        co=[x - 1 for x in values[8:16]],
        ep=values[16:28],
        eo=[x - 1 for x in values[28:40]],
    )
    if cube.verify() != 0:
        raise ValueError("target does not describe a legal cube in Kociemba order")
    return cube


def apply_moves(formula: str) -> CubieCube:
    cube = CubieCube()
    for word in formula.split():
        if not re.fullmatch(r"[URFDLB](?:2|')?", word):
            raise ValueError(f"invalid move: {word}")
        move = moveCube[FACES.index(word[0])]
        turns = 2 if word.endswith("2") else 3 if word.endswith("'") else 1
        for _ in range(turns):
            cube.multiply(move)
    return cube


def inverse_formula(formula: str) -> str:
    inverse = []
    for word in reversed(formula.split()):
        if word.endswith("2"):
            inverse.append(word)
        elif word.endswith("'"):
            inverse.append(word[0])
        else:
            inverse.append(word + "'")
    return " ".join(inverse)


def quarter_only(formula: str) -> str:
    """Expand a formula into a compact string of clockwise face letters."""
    notes = []
    for word in formula.split():
        if not re.fullmatch(r"[URFDLB](?:2|')?", word):
            raise ValueError(f"invalid move: {word}")
        count = 2 if word.endswith("2") else 3 if word.endswith("'") else 1
        notes.append(word[0] * count)
    return "".join(notes)


def target_hex(cube: CubieCube) -> str:
    return bytes(
        list(cube.cp)
        + [x + 1 for x in cube.co]
        + list(cube.ep)
        + [x + 1 for x in cube.eo]
    ).hex()


def inverse_cube(cube: CubieCube) -> CubieCube:
    result = CubieCube()
    cube.invCubieCube(result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="80 hexadecimal characters from the target prompt")
    args = parser.parse_args()
    target = parse_target(args.target)
    facelets = target.toFaceCube().to_String()
    to_solved = kociemba.solve(facelets)
    to_target = inverse_formula(to_solved)
    if target_hex(apply_moves(to_target)) != target_hex(target):
        raise AssertionError("face move sequence did not reproduce the target")
    compact = quarter_only(to_target)
    if target_hex(apply_moves(" ".join(compact))) != target_hex(target):
        raise AssertionError("quarter-only sequence did not reproduce the target")
    print("facelets:  ", facelets)
    print("to_target: ", to_target)
    print("to_solved: ", to_solved)
    print("quarter_only:", compact)
    print("inverse_hex: ", target_hex(inverse_cube(target)))


if __name__ == "__main__":
    main()
