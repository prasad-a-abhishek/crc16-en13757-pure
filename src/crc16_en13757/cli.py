"""CLI: ``python3 -m crc16_en13757 --data <hex> [--self-test]``.

Examples:

    $ python3 -m crc16_en13757 --data 31323334353637383939
    0xc2b7

    $ python3 -m crc16_en13757 --self-test
    Running 6 RevEng-canonical vectors...
    PASS: empty input          -> 0xffff
    PASS: 00                   -> 0xffff
    PASS: 01                   -> 0xc29a
    PASS: ff                   -> 0x53b7
    PASS: 00..09               -> 0x1078
    PASS: 123456789            -> 0xc2b7
    6/6 vectors passed.
"""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import __version__, crc

# RevEng-canonical vectors (also documented in seed_evidence.json).
VECTORS: list[tuple[str, bytes, int]] = [
    ("empty input", b"", 0xFFFF),
    ("00", b"\x00", 0xFFFF),
    ("01", b"\x01", 0xC29A),
    ("ff", b"\xff", 0x53B7),
    ("00..09", bytes(range(10)), 0x1078),
    ("123456789", b"123456789", 0xC2B7),
]


def _format_hex(value: int) -> str:
    return f"0x{value:04x}"


def _parse_hex(text: str) -> bytes:
    """Parse a hex string with optional whitespace into bytes."""
    cleaned = text.replace(" ", "").replace("\n", "").replace("\t", "")
    if not cleaned:
        return b""
    if len(cleaned) % 2 != 0:
        raise ValueError("hex string must have even length")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"malformed hex input: {exc}") from exc


def cmd_data(args: argparse.Namespace) -> int:
    try:
        data = _parse_hex(args.data)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(_format_hex(crc(data)))
    return 0


def cmd_self_test(_args: argparse.Namespace) -> int:
    print(f"Running {len(VECTORS)} RevEng-canonical vectors...")
    failures = 0
    for label, payload, expected in VECTORS:
        actual = crc(payload)
        ok = actual == expected
        marker = "PASS" if ok else "FAIL"
        print(f"{marker}: {label:<18} -> {_format_hex(actual)}")
        if not ok:
            print(f"      expected {_format_hex(expected)}")
            failures += 1
    total = len(VECTORS)
    if failures == 0:
        print(f"{total}/{total} vectors passed.")
        return 0
    print(f"{failures}/{total} vectors FAILED.", file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m crc16_en13757",
        description=(
            "CRC-16/EN-13757 (Wireless M-Bus / OMS) reference CLI. "
            f"version {__version__}."
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--data",
        metavar="HEX",
        help="hex-encoded bytes to checksum (whitespace ignored)",
    )
    group.add_argument(
        "--self-test",
        action="store_true",
        help="run all RevEng-canonical vectors and exit",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"crc16_en13757 {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        return cmd_self_test(args)
    return cmd_data(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
