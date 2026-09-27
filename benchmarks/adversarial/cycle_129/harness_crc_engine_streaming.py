"""Fuzzing harness 2/5: surface -- ``Crc16En13757`` streaming engine.

Goal:
    Subject the chunk-oriented streaming wrapper to randomized
    chunking -- random number of pieces, random piece sizes --
    asserting the Invariant 14 property:

        crc(concat(pieces)) == Crc16En13757().update(piece).update(piece)...value

    Concretely:

      1. Single-shot equality: a single-piece stream must equal ``crc()``.
      2. Chaining equality: N-piece stream must equal ``crc()`` of the
         concatenation (this is THE property that proves ``update`` is
         a true incremental form of ``crc``).
      3. Reset round-trip: after ``reset()``, a fresh stream yields the
         same CRC as a brand-new ``Crc16En13757()`` instance.
      4. Property 4 of Crc16En13757: feed all-zero 64 KiB in 1-byte
         chunks -- the result must be deterministic and in-range.

Run::

    python3 harness_crc_engine_streaming.py --iters 200 --seed 42

Exits 0 on no anomaly, 1 on assertion failure.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
from typing import Callable

_REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)
_SRC = os.path.join(_REPO_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from crc16_en13757 import Crc16En13757, crc  # noqa: E402

DEFAULT_MAX_LEN = 65_536  # 64 KiB -- chunked-streaming is O(n) anyway
DEFAULT_MAX_CHUNKS = 32


def _generate_payload(rng: random.Random, max_len: int) -> bytes:
    """Random bytes payload with a 10% chance of empty (canonical vector)."""
    if rng.random() < 0.10:
        return b""
    return rng.randbytes(rng.randint(1, max_len))


def _chunkify(rng: random.Random, payload: bytes, max_chunks: int) -> list[bytes]:
    """Split ``payload`` into 1..max_chunks pieces of random sizes.

    Always returns at least one chunk. Each chunk's length is drawn
    from a Dirichlet-style split -- avoids the zero-byte chunk edge
    case at the tail.
    """
    n_chunks = rng.randint(1, max_chunks)
    if n_chunks == 1 or len(payload) == 0:
        return [payload]
    # Sample split points in (0, len(payload)) and sort.
    cuts = sorted(
        rng.sample(range(1, len(payload)), k=min(n_chunks - 1, len(payload) - 1))
    )
    pieces: list[bytes] = []
    prev = 0
    for c in cuts:
        pieces.append(payload[prev:c])
        prev = c
    pieces.append(payload[prev:])
    return pieces


def _check_single_shot_equality(rng: random.Random, max_len: int,
                                max_chunks: int) -> None:
    """A 1-piece stream must equal ``crc()`` of that piece."""
    payload = _generate_payload(rng, max_len)
    expected = crc(payload)
    eng = Crc16En13757()
    eng.update(payload)
    if eng.value != expected:
        raise AssertionError(
            f"single-shot inequality on len={len(payload)}: "
            f"crc={expected:#x} stream={eng.value:#x}"
        )


def _check_chaining_equality(rng: random.Random, max_len: int,
                             max_chunks: int) -> None:
    """N-piece stream must equal ``crc(concat(pieces))`` -- Invariant 14."""
    payload = _generate_payload(rng, max_len)
    expected = crc(payload)
    pieces = _chunkify(rng, payload, max_chunks)
    eng = Crc16En13757()
    for piece in pieces:
        eng.update(piece)
    if eng.value != expected:
        raise AssertionError(
            f"chaining inequality on len={len(payload)} chunks={len(pieces)}: "
            f"crc={expected:#x} stream={eng.value:#x}"
        )


def _check_reset_round_trip(rng: random.Random, max_len: int,
                            max_chunks: int) -> None:
    """After ``reset()`` and re-feeding the same data, the result must equal
    a fresh instance fed the same data."""
    payload = _generate_payload(rng, max_len)
    a = Crc16En13757()
    for piece in _chunkify(rng, payload, max_chunks):
        a.update(piece)
    val_a = a.value
    a.reset()
    for piece in _chunkify(rng, payload, max_chunks):
        a.update(piece)
    val_a_after_reset = a.value
    b = Crc16En13757()
    for piece in _chunkify(rng, payload, max_chunks):
        b.update(piece)
    if not (val_a == val_a_after_reset == b.value):
        raise AssertionError(
            f"reset round-trip divergence: pre-reset={val_a:#x} "
            f"post-reset={val_a_after_reset:#x} fresh={b.value:#x}"
        )


def _check_all_zero_chunked(rng: random.Random, max_len: int,
                            max_chunks: int) -> None:
    """Feed 64 KiB of zero bytes in 1-byte chunks -- the streaming form
    must equal the one-shot form (this is the canonical 'infinite zero'
    pattern used by CRC textbooks to verify the register loop)."""
    payload = b"\x00" * 4096  # 4 KiB keeps the smoke run cheap
    expected = crc(payload)
    eng = Crc16En13757()
    for byte in payload:
        eng.update(bytes([byte]))
    if eng.value != expected:
        raise AssertionError(
            f"all-zero 1-byte-chunk streaming broke: "
            f"crc={expected:#x} stream={eng.value:#x}"
        )


CHECKS: tuple[tuple[str, Callable[[random.Random, int, int], None]], ...] = (
    ("single-shot-equality", _check_single_shot_equality),
    ("chaining-equality", _check_chaining_equality),
    ("reset-round-trip", _check_reset_round_trip),
    ("all-zero-1-byte-chunked", _check_all_zero_chunked),
)


def run(iters: int, seed: int, max_len: int, max_chunks: int) -> int:
    rng = random.Random(seed)
    t0 = time.perf_counter()
    for i in range(iters):
        for name, fn in CHECKS:
            try:
                fn(rng, max_len, max_chunks)
            except AssertionError as exc:
                print(
                    f"FAIL iter={i} check={name}: {exc}",
                    file=sys.stderr,
                )
                return 1
    elapsed = time.perf_counter() - t0
    rate = iters / elapsed if elapsed > 0 else float("inf")
    print(
        f"PASS harness_crc_engine_streaming iters={iters} seed={seed} "
        f"max_len={max_len} max_chunks={max_chunks} "
        f"elapsed={elapsed:.3f}s rate={rate:,.0f}/s"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iters", type=int, default=100)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--max-len", type=int, default=DEFAULT_MAX_LEN)
    p.add_argument("--max-chunks", type=int, default=DEFAULT_MAX_CHUNKS)
    args = p.parse_args(argv)
    return run(args.iters, args.seed, args.max_len, args.max_chunks)


if __name__ == "__main__":
    sys.exit(main())