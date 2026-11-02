"""Command line entry point for the Hexachord field kit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.exceptions import InvalidTag

from hexachord_lab.recovery import decrypt, load_final, load_records, selftest
from hexachord_lab.session import run


def open_seal(records: Path, final: Path) -> int:
    shares = load_records(records)
    if len(shares) < 18:
        print(f"INSUFFICIENT_SHARES {len(shares)}/18")
        return 2
    try:
        plaintext = decrypt(load_final(final), shares)
    except InvalidTag:
        print("SEAL_INVALID: inspect connection continuity, receipt integrity and finale framing")
        return 3
    flag = plaintext.decode("utf-8")
    if not (flag.startswith("flag{") and flag.endswith("}")):
        print(f"UNEXPECTED_PLAINTEXT {flag!r}")
        return 4
    print(f"FLAG {flag}")
    return 0


def capture(host: str, port: int, out: Path) -> int:
    options = argparse.Namespace(
        host=host, port=port, out=out, max_chapters=20,
        timeout=25.0, solver_timeout=25.0, symmetry_timeout=8.0,
        solver_mode="hybrid", compact_timeout=19.0,
        compact_symmetry_timeout=5.0, chapter_solve_budget=26.0,
        skip_unsolved=True, stop_after_credits=0,
        skip_after_credits=18, probe_source=None,
    )
    run(options)
    records = out / "chapters.jsonl"
    final = out / "final_response.bin"
    if not final.is_file():
        print("NO_SETTLEMENT: inspect the chapter ledger")
        return 2
    credited = sum(json.loads(line).get("status") in ("credited", "final_received")
                   for line in records.read_text(encoding="utf-8").splitlines())
    print(f"CREDITED {credited}/20")
    return open_seal(records, final)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    live = sub.add_parser("capture", help="collect one complete live session")
    live.add_argument("--host", required=True)
    live.add_argument("--port", required=True, type=int)
    live.add_argument("--out", required=True, type=Path)
    saved = sub.add_parser("open", help="open a saved settlement")
    saved.add_argument("--records", required=True, type=Path)
    saved.add_argument("--final", required=True, type=Path)
    sub.add_parser("check", help="exercise the local field model")
    args = parser.parse_args()
    if args.command == "check":
        selftest()
        return 0
    if args.command == "open":
        return open_seal(args.records, args.final)
    return capture(args.host, args.port, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
