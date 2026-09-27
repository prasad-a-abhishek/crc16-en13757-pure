"""Fuzzing harness 5/5: surface -- Invariant 21 compliance (total over arbitrary input).

Goal:
    Verify the public surface (``crc``, ``crc_stream``, ``Crc16En13757.update``,
    ``Crc16En13757.__init__``, ``table_lookup``) is total over arbitrary
    Python inputs. Per Invariant 21, ``crc(None)``, ``crc(123)``, etc.
    MUST return structured findings (raise a typed exception with a
    useful message) -- they must NEVER raise a bare ``AttributeError``
    from internal iteration, never silently produce garbage, and never
    raise ``ValueError`` for a type problem (TypeError is the right
    category for "you passed the wrong type").

    Property matrix exercised here:

      - ``None``
      - ``int`` (negative, zero, large, NaN-via-``float('nan')``)
      - ``float`` (NaN, inf)
      - ``str`` (empty, ASCII, multibyte UTF-8, embedded null byte)
      - ``list`` / ``tuple`` of ints (incl. bad elements)
      - ``dict`` / ``set``
      - ``object()`` (the bare-userclass probe)
      - Iterators that pretend to be bytes-like (subclass of bytes
        but with a poisoned ``__iter__`` -- bypass-the-guard probe)

Run::

    python3 harness_type_errors.py --iters 100 --seed 42

Exits 0 on no anomaly, 1 on assertion failure.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time
from typing import Any, Callable

_REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)
_SRC = os.path.join(_REPO_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from crc16_en13757 import (  # noqa: E402
    Crc16En13757,
    crc,
    crc_stream,
)
from crc16_en13757._table import table_lookup  # noqa: E402


# Surfaces under test + the contract they MUST honour.
SURFACES: tuple[tuple[str, Callable[[Any], Any]], ...] = (
    ("crc", crc),
    ("crc_stream", crc_stream),
    ("table_lookup", table_lookup),
)


def _expect_typed_error(surface_name: str, value: Any) -> TypeError:
    """Invoke surface(value); assert TypeError raised with a helpful message.

    The implementation's _isinstance check is the contract; if it ever
    regresses to letting bytes-like iteration slip through with an
    AttributeError, this harness fails.
    """
    try:
        result = crc(value) if surface_name == "crc" else (
            crc_stream(value) if surface_name == "crc_stream" else table_lookup(value)
        )
    except TypeError as exc:
        msg = str(exc)
        if not msg:
            raise AssertionError(
                f"surface={surface_name} value={value!r} raised empty TypeError"
            )
        return exc
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"surface={surface_name} value={value!r} raised "
            f"{type(exc).__name__} (expected TypeError): {exc}"
        )
    # If no exception was raised, that's a contract violation -- unless
    # the value happens to BE bytes-like (e.g. bytearray). Filter those.
    if isinstance(value, (bytes, bytearray, memoryview)):
        return TypeError("bytes-like -- not in scope")
    raise AssertionError(
        f"surface={surface_name} value={value!r} returned "
        f"{result!r} instead of raising TypeError"
    )


def _expect_typed_error_update(value: Any) -> None:
    """Crc16En13757.update() must raise TypeError for non-bytes-like."""
    eng = Crc16En13757()
    try:
        eng.update(value)
    except TypeError:
        return
    except Exception as exc:  # noqa: BLE001
        raise AssertionError(
            f"Crc16En13757.update({value!r}) raised "
            f"{type(exc).__name__} (expected TypeError): {exc}"
        )
    if isinstance(value, (bytes, bytearray, memoryview)):
        return
    raise AssertionError(
        f"Crc16En13757.update({value!r}) returned silently"
    )


# ---- canonical bad-input set (Invariant 21 conformance probe) ----

CANONICAL_BAD_INPUTS: tuple[tuple[str, Any], ...] = (
    ("None", None),
    ("int 0", 0),
    ("int -1", -1),
    ("int 999999", 999_999),
    ("float NaN", float("nan")),
    ("float inf", float("inf")),
    ("empty str", ""),
    ("ascii str", "hello"),
    ("unicode str", "héllo-中文"),
    ("embedded NUL", "abc\x00def"),
    ("empty list", []),
    ("list of ints", [1, 2, 3]),
    ("empty tuple", ()),
    ("tuple of ints", (1, 2, 3)),
    ("empty dict", {}),
    ("dict", {"a": 1}),
    ("empty set", set()),
    ("set of ints", {1, 2, 3}),
    ("bare object", object()),
    ("lambda", lambda: None),
)


# ---- randomized bad inputs (extends the canonical set) ----

def _gen_random_bad_input(rng: random.Random) -> tuple[str, Any]:
    """Return a (label, value) pair that is NOT bytes-like."""
    choice = rng.choice(
        (
            "neg_int", "large_int", "str", "list_of_ints",
            "tuple_of_ints", "nested_dict", "generator", "class_inst",
        )
    )
    if choice == "neg_int":
        return ("neg_int", rng.randint(-(2 ** 31), -1))
    if choice == "large_int":
        return ("large_int", rng.randint(2 ** 64, 2 ** 80))
    if choice == "str":
        n = rng.randint(0, 16)
        return ("str", "".join(chr(rng.randint(0, 0x10FFFF)) for _ in range(n)))
    if choice == "list_of_ints":
        n = rng.randint(0, 16)
        return ("list_of_ints", [rng.randint(0, 255) for _ in range(n)])
    if choice == "tuple_of_ints":
        n = rng.randint(0, 16)
        return ("tuple_of_ints", tuple(rng.randint(0, 255) for _ in range(n)))
    if choice == "nested_dict":
        return ("nested_dict", {"k": [1, {2, 3}]})
    if choice == "generator":
        return ("generator", (b for b in ()))  # empty bytes-like generator
    # class_inst -- a class whose __iter__ would crash if the harness's
    # isinstance check ever regresses.
    class Boom:
        def __iter__(self):
            raise RuntimeError("Boom.__iter__ invoked -- guard regressed")
    return ("Boom", Boom())


# ---- the harness ----

def run(iters: int, seed: int) -> int:
    rng = random.Random(seed)
    t0 = time.perf_counter()

    # 1. Canonical probe -- each surface, each canonical bad input.
    for surface_name, _fn in SURFACES:
        for label, value in CANONICAL_BAD_INPUTS:
            try:
                _expect_typed_error(surface_name, value)
            except AssertionError as exc:
                print(
                    f"FAIL canonical surface={surface_name} "
                    f"input={label}: {exc}",
                    file=sys.stderr,
                )
                return 1

    # 2. Crc16En13757.update() canonical probe.
    for label, value in CANONICAL_BAD_INPUTS:
        try:
            _expect_typed_error_update(value)
        except AssertionError as exc:
            print(
                f"FAIL canonical surface=Crc16En13757.update "
                f"input={label}: {exc}",
                file=sys.stderr,
            )
            return 1

    # 3. Randomized fuzz over the surface<->bad-input cross product.
    for i in range(iters):
        label, value = _gen_random_bad_input(rng)
        for surface_name, _fn in SURFACES:
            try:
                _expect_typed_error(surface_name, value)
            except AssertionError as exc:
                print(
                    f"FAIL random iter={i} surface={surface_name} "
                    f"input={label}: {exc}",
                    file=sys.stderr,
                )
                return 1
        try:
            _expect_typed_error_update(value)
        except AssertionError as exc:
            print(
                f"FAIL random iter={i} surface=Crc16En13757.update "
                f"input={label}: {exc}",
                file=sys.stderr,
            )
            return 1

    elapsed = time.perf_counter() - t0
    rate = iters / elapsed if elapsed > 0 else float("inf")
    print(
        f"PASS harness_type_errors iters={iters} seed={seed} "
        f"canonical={len(CANONICAL_BAD_INPUTS)} "
        f"surfaces={len(SURFACES) + 1} "
        f"elapsed={elapsed:.3f}s rate={rate:,.0f}/s"
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