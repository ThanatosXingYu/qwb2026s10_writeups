"""Checker search and dual-use spell planning."""

from __future__ import annotations

from dataclasses import dataclass
import time

import psutil

from hexachord_lab.geometry.bidir_reuse import ReusableSolver
from hexachord_lab.geometry.checker_model import State
from hexachord_lab.geometry.compact_solver import CompactSolver
from hexachord_lab.geometry.symmetry_solve import ROTATIONS, REFLECTIONS, inverse, transform
from hexachord_lab.exploit.pivot3_encode import encode as encode_pivot3
from hexachord_lab.exploit.pivot_leave import encode as encode_leave
from hexachord_lab.exploit.pivot_loopback import encode as encode_loopback
from hexachord_lab.exploit.pivot_pop_rm import encode as encode_pop_rm
from hexachord_lab.exploit.pivot_retimm import encode as encode_retimm

@dataclass(frozen=True)
class Plan:
    formula: str
    spell: bytes
    stack_skip: int
    spray_delta: int
    mode: str
    source: str
    seconds: float


class SolverHandle:
    def __init__(self, mode: str):
        self.mode = mode
        self.search = (CompactSolver(12, 10) if mode == "compact"
                       else ReusableSolver(10, 9))
        self.strong = CompactSolver(12, 10) if mode == "hybrid" else None

    def prepare(self) -> tuple[float, int, int]:
        start = time.monotonic()
        self.search.prepare()
        forward = self.search.forward
        states = forward.count if self.mode == "compact" else len(forward)
        if self.strong is not None:
            self.strong.prepare()
            states += self.strong.forward.count
        return (time.monotonic() - start, states,
                psutil.Process().memory_info().rss)


def encode_formula(formula: str, source: str, seconds: float) -> Plan | None:
    for encoder, mode, delta in (
        (encode_pivot3, "pop-pop-rsp-ret", 0),
        (encode_leave, "pop-pop-rbp-leave-ret", -8),
        (encode_pop_rm, "pop-pop-rsp-modrm-ret", 0),
    ):
        try:
            result = encoder(formula)
        except ValueError:
            continue
        spell = result if isinstance(result, bytes) else result.spell
        assert len(spell) <= 31
        return Plan(formula, spell, 0, delta, mode, source, seconds)
    try:
        result = encode_retimm(formula, maximum_skip=1)
    except ValueError:
        pass
    else:
        return Plan(formula, result.spell, result.skip, 0,
                    "pop-pop-rsp-ret-imm", source, seconds)
    try:
        result = encode_loopback(formula)
    except ValueError:
        return None
    return Plan(formula, result.spell, result.stack_skip,
                result.spray_delta, "hidden-ret-loopback", source, seconds)


def search_views(target: str, search,
                 primary_timeout: float, symmetry_timeout: float,
                 source_prefix: str, start: float,
                 deadline: float, identity: bool = True,
                 symmetries: bool = True) -> Plan | None:
    target_state = State.from_hex(target)
    def search_one(state_hex: str, preferred_timeout: float) -> str | None:
        remaining = deadline - time.monotonic() - 1.0
        if remaining <= 1.0:
            return None
        return search.solve(state_hex, min(preferred_timeout, remaining))

    if identity:
        formula = search_one(target, primary_timeout)
        if formula is not None:
            plan = encode_formula(formula, source_prefix + "identity",
                                  time.monotonic() - start)
            if plan is not None:
                assert State().play(plan.spell) == target_state
                return plan
    if not symmetries:
        return None
    for view, rotation in enumerate(ROTATIONS):
        if time.monotonic() >= deadline - 2.0:
            return None
        rotated = transform(target_state, rotation)
        found = search_one(rotated.hex(), symmetry_timeout)
        if found is None:
            continue
        original = "".join(rotation.inverse_face(c) for c in found)
        plan = encode_formula(original, f"{source_prefix}rotation-{view}",
                              time.monotonic() - start)
        if plan is not None:
            assert State().play(plan.spell) == target_state
            return plan
    inverted = inverse(target_state)
    for view, reflection in enumerate(REFLECTIONS):
        if time.monotonic() >= deadline - 2.0:
            return None
        reflected_inverse = transform(inverted, reflection)
        found = search_one(reflected_inverse.hex(), symmetry_timeout)
        if found is None:
            continue
        original = "".join(reflection.inverse_face(c)
                           for c in reversed(found))
        plan = encode_formula(original, f"{source_prefix}reflection-{view}",
                              time.monotonic() - start)
        if plan is not None:
            assert State().play(plan.spell) == target_state
            return plan
    return None


def solve_plan(target: str, solver: SolverHandle,
               primary_timeout: float, symmetry_timeout: float,
               compact_timeout: float, compact_symmetry_timeout: float,
               chapter_solve_budget: float) -> Plan | None:
    start = time.monotonic()
    deadline = start + chapter_solve_budget
    if solver.mode == "compact":
        return search_views(target, solver.search, compact_timeout,
                            compact_symmetry_timeout, "compact-", start,
                            deadline)
    if solver.mode == "fast":
        return search_views(target, solver.search, primary_timeout,
                            symmetry_timeout, "", start, deadline)
    # Both tables are prepared before connecting. Try cheap fast identity,
    # then strong identity, and spend the remainder on alternate views.
    assert solver.strong is not None
    plan = search_views(target, solver.search, min(primary_timeout, 2), 0,
                        "", start, deadline, symmetries=False)
    if plan is not None:
        return plan
    plan = search_views(target, solver.strong, compact_timeout, 0,
                        "compact-", start, deadline, symmetries=False)
    if plan is not None:
        return plan
    plan = search_views(target, solver.search, 0, symmetry_timeout,
                        "", start, deadline, identity=False)
    if plan is not None:
        return plan
    return search_views(target, solver.strong, 0, compact_symmetry_timeout,
                        "compact-", start, deadline, identity=False)
