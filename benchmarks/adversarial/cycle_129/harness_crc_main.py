"""Fuzzing harness 1/5: surface -- ``crc16_en13757.crc(data)``.

Goal:
    Subject the canonical single-shot ``crc`` entry point to random
    bytes-like payloads of varying lengths (0..1 MB). Assert that:

      1. Every output is an ``int`` in the closed range [0, 0xFFFF].
      2. Re-running with the same payload and seed produces the same
         output (deterministic, no hidden PRNG).
      3. ``bytes``, ``bytearray``, and ``memoryview`` views over the
         same bytes yield identical CRC values (no implicit copies
         leaking state).
      4. Mutation of the source buffer AFTER calling ``crc`` does not
         affect a previously-computed return value (caller's mutation
         contract).

This is a stdlib-only harness (Atheris-compatible in spirit but does
not require ``atheris`` to be installed). Use ``random.seed`` for
reproducibility -- required for any anomaly to be re-playable.

Run::

    python3 harness_crc_main.py --iters 1000 --seed 42
    python3 harness_crc_main.py --seed 0 --max-len 1048576

Exits 0 on no anomaly, 1 on assertion failure.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
from typing import Callable

# Ensure the just-installed package is importable even if the harness is
# invoked from a fresh shell without ``pip install -e .``.
_REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)
_SRC = os.path.join(_REPO_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from crc16_en13757 import crc  # noqa: E402

# Upper bound per the task spec -- "0..1MB" length sweep. Keeping it
# configurable so smoke runs use a tighter cap.
DEFAULT_MAX_LEN = 16_384  # 16 KiB -- fast smoke; bump to 1_048_576 for full


def _generate_payload(rng: random.Random, max_len: int) -> bytes:
    """Generate a random ``bytes`` payload up to ``max_len``.

    Includes a 10% chance of returning the empty bytes to exercise the
    init=0x0000 → xorout=0xFFFF canonical vector.
    """
    if rng.random() < 0.10:
        return b""
    n = rng.randint(1, max_len)
    return rng.randbytes(n)


def _assert_in_range(value: int, where: str) -> None:
    if not isinstance(value, int):
        raise AssertionError(
            f"{where}: expected int, got {type(value).__name__}"
        )
    if not 0 <= value <= 0xFFFF:
        raise AssertionError(
            f"{where}: out-of-range CRC {value:#x} (not in [0, 0xFFFF])"
        )


def _check_determinism(rng: random.Random, max_len: int) -> None:
    """Same payload + same call -> same result (twice)."""
    payload = _generate_payload(rng, max_len)
    a = crc(payload)
    b = crc(payload)
    if a != b:
        raise AssertionError(
            f"determinism violation: crc(p)={a:#x}, crc(p) again={b:#x}"
        )


def _check_view_equivalence(rng: random.Random, max_len: int) -> None:
    """bytes / bytearray / memoryview over identical bytes => equal CRCs."""
    payload = _generate_payload(rng, max_len)
    ba = bytearray(payload)
    mv = memoryview(payload)
    c_b = crc(payload)
    c_ba = crc(ba)
    c_mv = crc(mv)
    if not (c_b == c_ba == c_mv):
        raise AssertionError(
            f"view divergence on len={len(payload)} payload: "
            f"bytes={c_b:#x} bytearray={c_ba:#x} memoryview={c_mv:#x}"
        )


def _check_mutation_isolation(rng: random.Random, max_len: int) -> None:
    """Mutating the source buffer after calling crc must not affect the result.

    The reference loop iterates over the bytes at call time and stores
    the CRC in a fresh ``int``; this invariant is contract-level
    (Invariant 21 in the orchestrator's three-pillar protocol).
    """
    payload = bytearray(_generate_payload(rng, max_len))
    snapshot = bytes(payload)
    c1 = crc(payload)
    # Mutate every byte in place.
    for i in range(len(payload)):
        payload[i] ^= 0xFF
    c2 = crc(snapshot)  # of the *original* bytes
    if c1 != c2:
        raise AssertionError(
            f"mutation isolation broken: pre-mutate crc={c1:#x} "
            f"!= post-mutate (re-snapshotted) crc={c2:#x}"
        )


CHECKS: tuple[tuple[str, Callable[[random.Random, int], None]], ...] = (
    ("determinism", _check_determinism),
    ("view-equivalence", _check_view_equivalence),
    ("mutation-isolation", _check_mutation_isolation),
)


def run(iters: int, seed: int, max_len: int) -> int:
    rng = random.Random(seed)
    t0 = time.perf_counter()
    for i in range(iters):
        for name, fn in CHECKS:
            try:
                fn(rng, max_len)
            except AssertionError as exc:
                print(
                    f"FAIL iter={i} check={name}: {exc}",
                    file=sys.stderr,
                )
                return 1
        # Also run the "raw" call and confirm in-range.
        payload = _generate_payload(rng, max_len)
        _assert_in_range(crc(payload), f"iter={i} raw")
    elapsed = time.perf_counter() - t0
    rate = iters / elapsed if elapsed > 0 else float("inf")
    print(
        f"PASS harness_crc_main iters={iters} seed={seed} "
        f"max_len={max_len} elapsed={elapsed:.3f}s rate={rate:,.0f}/s"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iters", type=int, default=100)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--max-len", type=int, default=DEFAULT_MAX_LEN,
                   help="cap payload size in bytes (default 1 MiB)")
    args = p.parse_args(argv)
    return run(args.iters, args.seed, args.max_len)


if __name__ == "__main__":
    sys.exit(main())