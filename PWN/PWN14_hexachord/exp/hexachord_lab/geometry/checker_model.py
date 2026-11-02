"""Exact cubie transformation used by the Hexachord checker.

The checker reads raw bytes.  Each byte chooses one of six quarter turns by
its residue modulo six.  State bytes are cp, co, ep, eo in that order.
Orientations are one based: corner values 1/2/3 form the multiplicative
group of GF(4), while edge values 1/2 multiply modulo three.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


TABLE = Path(__file__).with_name("table_d1349e3779b97f4b.bin").read_bytes()
assert len(TABLE) == 0x118

CP = [TABLE[8 * m : 8 * (m + 1)] for m in range(6)]
CO = [TABLE[48 + 8 * m : 48 + 8 * (m + 1)] for m in range(6)]
EP = [TABLE[96 + 12 * m : 96 + 12 * (m + 1)] for m in range(6)]
EO = [TABLE[168 + 12 * m : 168 + 12 * (m + 1)] for m in range(6)]
FACES = "URFDLB"


def gf4mul(a: int, b: int) -> int:
    assert a in (1, 2, 3) and b in (1, 2, 3)
    return (1, 2, 3)[((1, 2, 3).index(a) + (1, 2, 3).index(b)) % 3]


@dataclass(frozen=True)
class State:
    cp: bytes = bytes(range(8))
    co: bytes = bytes([1] * 8)
    ep: bytes = bytes(range(12))
    eo: bytes = bytes([1] * 12)

    @classmethod
    def from_hex(cls, value: str) -> "State":
        b = bytes.fromhex(value)
        assert len(b) == 40
        return cls(b[:8], b[8:16], b[16:28], b[28:40])

    def hex(self) -> str:
        return (self.cp + self.co + self.ep + self.eo).hex()

    def move(self, m: int) -> "State":
        m %= 6
        return State(
            bytes(self.cp[i] for i in CP[m]),
            bytes(gf4mul(self.co[i], CO[m][j]) for j, i in enumerate(CP[m])),
            bytes(self.ep[i] for i in EP[m]),
            bytes((self.eo[i] * EO[m][j]) % 3 for j, i in enumerate(EP[m])),
        )

    def play(self, actions: bytes | str) -> "State":
        state = self
        for action in actions:
            state = state.move(FACES.index(action) if isinstance(action, str) else action)
        return state


if __name__ == "__main__":
    import sys
    moves = sys.argv[1] if len(sys.argv) > 1 else ""
    print(State().play(moves).hex())
