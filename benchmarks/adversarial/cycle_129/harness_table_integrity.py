"""Fuzzing harness 3/5: surface -- ``TABLE`` module attribute (256-entry lookup).

Goal:
    Verify the lookup table shipped in ``crc16_en13757._table.TABLE``
    is byte-exact equal to an INDEPENDENTLY-recomputed reference for
    each of the 256 byte values, computed from the documented
    RevEng polynomial 0x3D65 (normal-form, un-reflected, MSB-first).

    Independence test: the reference in this file is computed by a
    separate algorithm (loop i in 0..255, shift by 8 bits, XOR POLY in
    MSB-first order) and asserted against the imported TABLE. If the
    implementation's table is ever swapped, mirrored, or stored with a
    reflected polynomial, the first non-matching byte raises
    AssertionError.

    Additional invariant:

      - Every entry of TABLE is an int in [0, 0xFFFF].
      - TABLE has length exactly 256.
      - TABLE is immutable (a ``tuple``).
      - For every (i, j) with i != j, TABLE[i] != TABLE[j] (per-byte
        uniqueness -- a constant table would prove the poly is wrong).

Run::

    python3 harness_table_integrity.py --iters 100 --seed 42

Exits 0 on no anomaly, 1 on assertion failure.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time

_REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)
_SRC = os.path.join(_REPO_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from crc16_en13757 import TABLE  # noqa: E402
from crc16_en13757.core import POLY  # noqa: E402

# Hard-coded sanity: this is the RevEng canonical row for CRC-16/EN-13757
# (Wireless M-Bus / OMS). If POLY moves, the harness's recomputed table
# will silently follow the import -- so we hard-pin a second copy here
# that asserts against POLY as a sanity check.
_REFERENCE_POLY = 0x3D65


def _reference_table(poly: int) -> tuple[int, ...]:
    """Compute the 256-entry table from scratch using the same MSB-first
    algorithm the implementation uses, but as a STANDALONE function so
    any code-level bug in the implementation cannot also affect this
    reference. Same algorithm, different code = cross-check."""
    table: list[int] = []
    for i in range(256):
        crc = (i << 8) & 0xFFFF
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ poly) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
        table.append(crc)
    return tuple(table)


def _check_shape() -> None:
    """TABLE must be a tuple of exactly 256 ints in [0, 0xFFFF]."""
    if not isinstance(TABLE, tuple):
        raise AssertionError(
            f"TABLE type: expected tuple, got {type(TABLE).__name__}"
        )
    if len(TABLE) != 256:
        raise AssertionError(f"TABLE length: expected 256, got {len(TABLE)}")
    for idx, entry in enumerate(TABLE):
        if not isinstance(entry, int):
            raise AssertionError(
                f"TABLE[{idx}] type: expected int, got {type(entry).__name__}"
            )
        if not 0 <= entry <= 0xFFFF:
            raise AssertionError(
                f"TABLE[{idx}] out-of-range: {entry:#x}"
            )


def _check_polynomial_pin() -> None:
    """The reference polynomial must be 0x3D65 (RevEng CRC-16/EN-13757)."""
    if POLY != _REFERENCE_POLY:
        raise AssertionError(
            f"POLY diverged from RevEng canonical: got {POLY:#x}, "
            f"expected {_REFERENCE_POLY:#x}"
        )


def _check_table_matches_reference() -> None:
    """Every entry of TABLE must equal an independently-recomputed reference."""
    ref = _reference_table(_REFERENCE_POLY)
    mismatches = [(i, TABLE[i], ref[i]) for i in range(256) if TABLE[i] != ref[i]]
    if mismatches:
        sample = mismatches[:5]
        raise AssertionError(
            f"TABLE divergence from reference: {len(mismatches)} entries "
            f"differ; sample={sample}"
        )


def _check_byte_uniqueness() -> None:
    """No two TABLE entries may be equal -- a duplicated entry would prove
    the polynomial table is over a degenerate quotient ring (impossible
    for a non-zero 16-bit poly, but worth the O(n^2) cost)."""
    seen: dict[int, int] = {}
    for i, entry in enumerate(TABLE):
        if entry in seen:
            raise AssertionError(
                f"TABLE not injective: TABLE[{seen[entry]}] == TABLE[{i}] == {entry:#x}"
            )
        seen[entry] = i


def _check_table_driven_matches_bitwise(rng: random.Random, iters: int) -> None:
    """For random payloads, ``table_lookup(p)`` must equal ``crc(p)``.

    The implementation's ``_table.table_lookup`` and ``core.crc`` are
    deliberately independent code paths -- both must agree on every
    input. (Note: this also imports crc indirectly to keep the harness
    self-contained rather than depending on which module's source is
    "the truth".)
    """
    # Imported inside the check so a future move doesn't break the
    # import-time side of the harness.
    from crc16_en13757 import crc  # noqa: PLC0415
    from crc16_en13757._table import table_lookup  # noqa: PLC0415

    for i in range(iters):
        n = rng.randint(0, 1024)
        payload = rng.randbytes(n) if n else b""
        # Use a separate "raw" check via a re-implemented bit-by-bit
        # loop just to triple-confirm. We don't want a hidden drift
        # between crc() and table_lookup().
        reg = 0
        for byte in payload:
            reg ^= byte << 8
            for _ in range(8):
                if reg & 0x8000:
                    reg = ((reg << 1) ^ POLY) & 0xFFFF
                else:
                    reg = (reg << 1) & 0xFFFF
        expected = reg ^ 0xFFFF
        tl = table_lookup(payload)
        ref = crc(payload)
        if tl != expected or ref != expected:
            raise AssertionError(
                f"iter={i} payload_len={n} divergence: "
                f"table_lookup={tl:#x} crc={ref:#x} raw={expected:#x}"
            )


def run(iters: int, seed: int) -> int:
    rng = random.Random(seed)

    # Step 1: polynomial sanity pin.
    t0 = time.perf_counter()
    _check_polynomial_pin()
    # Step 2: shape check.
    _check_shape()
    # Step 3: reference cross-check (deterministic, not affected by seed).
    _check_table_matches_reference()
    # Step 4: injectivity.
    _check_byte_uniqueness()
    # Step 5: random fuzz against bit-by-bit reference.
    _check_table_driven_matches_bitwise(rng, iters)

    elapsed = time.perf_counter() - t0
    print(
        f"PASS harness_table_integrity iters={iters} seed={seed} "
        f"table_len=256 elapsed={elapsed:.3f}s"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iters", type=int, default=100)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args(argv)
    return run(args.iters, args.seed)


if __name__ == "__main__":
    sys.exit(main())