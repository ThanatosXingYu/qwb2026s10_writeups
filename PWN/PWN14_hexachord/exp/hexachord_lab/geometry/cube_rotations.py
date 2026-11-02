"""Physical cube rotations for Kociemba URFDLB facelet strings."""

from __future__ import annotations

from dataclasses import dataclass


Vector = tuple[int, int, int]
NORMALS: dict[str, Vector] = {
    "U": (0, 1, 0), "R": (1, 0, 0), "F": (0, 0, 1),
    "D": (0, -1, 0), "L": (-1, 0, 0), "B": (0, 0, -1),
}
NORMAL_TO_FACE = {normal: face for face, normal in NORMALS.items()}


def dot(a: Vector, b: Vector) -> int:
    return sum(x * y for x, y in zip(a, b))


def cross(a: Vector, b: Vector) -> Vector:
    return (a[1]*b[2] - a[2]*b[1],
            a[2]*b[0] - a[0]*b[2],
            a[0]*b[1] - a[1]*b[0])


def sticker(face: str, row: int, col: int) -> tuple[Vector, Vector]:
    if face == "U":
        return ((col-1, 1, row-1), NORMALS[face])
    if face == "R":
        return ((1, 1-row, 1-col), NORMALS[face])
    if face == "F":
        return ((col-1, 1-row, 1), NORMALS[face])
    if face == "D":
        return ((col-1, -1, 1-row), NORMALS[face])
    if face == "L":
        return ((-1, 1-row, col-1), NORMALS[face])
    if face == "B":
        return ((1-col, 1-row, -1), NORMALS[face])
    raise ValueError(face)


STICKERS = [sticker(face, row, col)
            for face in "URFDLB" for row in range(3) for col in range(3)]
STICKER_TO_INDEX = {pair: i for i, pair in enumerate(STICKERS)}
assert len(STICKER_TO_INDEX) == 54


@dataclass(frozen=True)
class Rotation:
    new_x: Vector
    new_y: Vector
    new_z: Vector
    chirality: int = 1

    def vector(self, v: Vector) -> Vector:
        return tuple(v[0]*self.new_x[i] + v[1]*self.new_y[i] +
                     v[2]*self.new_z[i] for i in range(3))  # type: ignore[return-value]

    def face(self, name: str) -> str:
        return NORMAL_TO_FACE[self.vector(NORMALS[name])]

    def inverse_face(self, name: str) -> str:
        return next(old for old in "URFDLB" if self.face(old) == name)

    def facelets(self, original: str) -> str:
        if len(original) != 54:
            raise ValueError("facelet string must contain 54 stickers")
        output = [""] * 54
        for i, (position, normal) in enumerate(STICKERS):
            destination = STICKER_TO_INDEX[(self.vector(position),
                                             self.vector(normal))]
            output[destination] = self.face(original[i])
        return "".join(output)

    def inverse_moves(self, formula: str) -> str:
        output = []
        for word in formula.split():
            suffix = word[1:]
            if self.chirality < 0 and suffix != "2":
                suffix = "" if suffix == "'" else "'"
            output.append(self.inverse_face(word[0]) + suffix)
        return " ".join(output)


def all_rotations() -> list[Rotation]:
    result = [Rotation(x, y, cross(x, y))
              for x in NORMALS.values() for y in NORMALS.values()
              if dot(x, y) == 0]
    assert len(result) == 24
    return result


def all_symmetries() -> list[Rotation]:
    rotations = all_rotations()
    reflections = [Rotation(x, y, tuple(-v for v in cross(x, y)), -1)
                   for x in NORMALS.values() for y in NORMALS.values()
                   if dot(x, y) == 0]
    assert len(reflections) == 24
    return rotations + reflections
