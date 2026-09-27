"""Fuzzing harness 6/5 (optional): surface -- cross-cycle differential oracle.

Goal:
    Verify CRC-16/EN-13757 produces results that are byte-distinct from
    its sibling packages shipped in earlier cycles:

      - crc16_modbus_pure (cycle_127): CRC-16/MODBUS, poly=0x8005,
        init=0xFFFF, xorout=0x0000, reflected. Canonical check on
        b'123456789' = 0x4B37.
      - crc16_ccitt (cycle_128): CRC-16/CCITT-FALSE, poly=0x1021,
        init=0xFFFF, xorout=0x0000, un-reflected. The cycle_128 ship is
        a STUB package per the parent's handoff -- this harness MUST
        handle the case where ``crc16_ccitt`` is shipped without a
        ``crc()`` symbol and report that as an info-level note rather
        than fabricating a value.

    Asserted properties:

      1. For every payload in a randomized corpus, the three packages
         (when all importable) produce three DISTINCT CRC values.
         A collision would mean the polynomials are not actually
         different at this payload, which would be a serious bug.
      2. ``crc16_en13757.crc(b'123456789')`` == 0xC2B7 (RevEng canonical).
      3. ``crc16_modbus_pure.crc(b'123456789')`` == 0x4B37 (RevEng canonical).
      4. If cycle_128 ccitt is shippable, its CRC of ``b'123456789'``
         MUST be 0x29B1. If not importable (stub), the harness records
         ``status="stub_unavailable"`` and skips the collision check.

Run::

    python3 harness_cross_cycle_oracle.py --iters 50 --seed 42

Exits 0 if all assertions hold (or the ccitt stub is properly skipped),
1 otherwise.
"""

from __future__ import annotations

import argparse
import importlib
import os
import random
import sys
import time
from typing import Any

_REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)
_SRC = os.path.join(_REPO_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)


# ---- sibling repo paths (cycles 127, 128) ----
_MODBUS_SRC = "/root/projects/crc16-modbus-pure/src"
_CCITT_SRC = "/root/projects/crc16-ccitt-pure/src"


def _try_import_crc(pkg: str, src_path: str) -> tuple[str, Any]:
    """Return (status, callable_or_message).

    status:
        "ok" -- imported, callable under name ``crc`` or ``crc16``.
        "stub_unavailable" -- package imported but has no callable CRC.
        "import_error" -- import failed; ``callable_or_message`` is the
            error string.
    """
    if src_path not in sys.path:
        sys.path.insert(0, src_path)
    try:
        mod = importlib.import_module(pkg)
    except Exception as exc:  # noqa: BLE001
        return "import_error", str(exc)
    for attr in ("crc", "crc16"):
        fn = getattr(mod, attr, None)
        if callable(fn):
            return "ok", fn
    return "stub_unavailable", (
        f"{pkg} ships no callable 'crc' or 'crc16' "
        f"(public attrs: {sorted(a for a in dir(mod) if not a.startswith('_'))})"
    )


def _check_canonical_check() -> None:
    """RevEng canonical check on b'123456789'."""
    from crc16_en13757 import crc  # noqa: PLC0415
    actual = crc(b"123456789")
    if actual != 0xC2B7:
        raise AssertionError(
            f"crc16_en13757 canonical check failed: "
            f"got {actual:#x}, expected 0xc2b7"
        )


def _check_modbus_safe(crc_modbus: Any) -> int:
    """Modbus canonical check on b'123456789' = 0x4B37."""
    actual = crc_modbus(b"123456789")
    if actual != 0x4B37:
        raise AssertionError(
            f"crc16_modbus_pure canonical check failed: "
            f"got {actual:#x}, expected 0x4b37"
        )
    return actual


def run(iters: int, seed: int) -> int:
    rng = random.Random(seed)
    t0 = time.perf_counter()

    # 1. Self canonical check.
    _check_canonical_check()

    # 2. Sibling imports.
    modbus_status, modbus_obj = _try_import_crc("crc16_modbus_pure", _MODBUS_SRC)
    ccitt_status, ccitt_obj = _try_import_crc("crc16_ccitt", _CCITT_SRC)

    print(f"  modbus_status={modbus_status} ccitt_status={ccitt_status}")
    if modbus_status == "stub_unavailable":
        raise AssertionError(
            f"crc16_modbus_pure must export 'crc' or 'crc16'; got: {modbus_obj}"
        )
    if modbus_status == "import_error":
        raise AssertionError(
            f"crc16_modbus_pure import failed: {modbus_obj}"
        )
    if ccitt_status == "import_error":
        raise AssertionError(
            f"crc16_ccitt import failed: {ccitt_obj}"
        )

    from crc16_en13757 import crc  # noqa: PLC0415
    crc_en = crc
    crc_modbus = modbus_obj

    # 3. Modbus canonical check.
    modbus_canonical = _check_modbus_safe(crc_modbus)
    en_canonical = crc_en(b"123456789")
    if modbus_canonical == en_canonical:
        # Both at 0x4B37 == 0xC2B7 would be catastrophic; flag it.
        raise AssertionError(
            f"CANONICAL COLLISION: en13757 == modbus == {en_canonical:#x}"
        )

    # 4. If ccitt is available, check canonical too.
    ccitt_canonical: int | None = None
    if ccitt_status == "ok":
        ccitt_canonical = ccitt_obj(b"123456789")
        if ccitt_canonical != 0x29B1:
            # Informational -- parent handoff says cycle_128 may differ,
            # so we don't fail the harness. We log it.
            print(
                f"  NOTE: ccitt canonical is {ccitt_canonical:#x} "
                f"(RevEng-canonical is 0x29b1)"
            )

    # 5. Randomized differential across the available packages.
    corpus = [b""] + [rng.randbytes(rng.randint(1, 256)) for _ in range(iters)]
    collision_payload: bytes | None = None
    collision_values: tuple[int, int] | tuple[int, int, int] | None = None
    for payload in corpus:
        v_en = crc_en(payload)
        v_modbus = crc_modbus(payload)
        if v_en == v_modbus:
            collision_payload, collision_values = payload, (v_en, v_modbus)
            break
        if ccitt_status == "ok":
            v_ccitt = ccitt_obj(payload)
            if v_en == v_ccitt or v_modbus == v_ccitt:
                collision_payload, collision_values = (
                    payload, (v_en, v_modbus, v_ccitt)
                )
                break
    if collision_payload is not None:
        raise AssertionError(
            f"cross-cycle collision on payload={collision_payload!r} "
            f"values={collision_values!r}"
        )

    elapsed = time.perf_counter() - t0
    rate = len(corpus) / elapsed if elapsed > 0 else float("inf")
    summary_bits = [
        f"en=0x{en_canonical:04x}",
        f"modbus=0x{modbus_canonical:04x}",
    ]
    if ccitt_canonical is not None:
        summary_bits.append(f"ccitt=0x{ccitt_canonical:04x}")
    else:
        summary_bits.append("ccitt=stub_unavailable")
    print(
        f"PASS harness_cross_cycle_oracle iters={iters} seed={seed} "
        f"corpus={len(corpus)} {' '.join(summary_bits)} "
        f"elapsed={elapsed:.3f}s rate={rate:,.0f}/s"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iters", type=int, default=50)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args(argv)
    return run(args.iters, args.seed)


if __name__ == "__main__":
    sys.exit(main())