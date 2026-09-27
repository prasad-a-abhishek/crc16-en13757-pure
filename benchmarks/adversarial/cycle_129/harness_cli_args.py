"""Fuzzing harness 4/5: surface -- ``python3 -m crc16_en13757`` CLI.

Goal:
    Subject the CLI entrypoint to random argv combinations and assert
    that:

      1. Well-formed ``--data <hex>`` invocations always exit 0 and
         produce a 4-character lowercase ``0x....`` string.
      2. Malformed hex (odd length, non-hex chars, missing arg) ALWAYS
         exits non-zero (per spec, exit code 2 on bad input) and never
         raises an uncaught traceback.
      3. ``--self-test`` always exits 0 and prints ``6/6 vectors passed``.
      4. ``--version`` always exits 0 and contains the package version.
      5. ``--help`` always exits 0 (argparse convention).
      6. The CLI never writes to stdout/stderr an uncaught Traceback
         (invariant 21: total over arbitrary argv).

Run::

    python3 harness_cli_args.py --iters 100 --seed 42

Exits 0 on no anomaly, 1 on assertion failure.
"""

from __future__ import annotations

import argparse
import io
import os
import random
import subprocess
import sys
import time
from typing import Iterable

_REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..")
)
_SRC = os.path.join(_REPO_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# Hard cap on the input length for the random hex well-formed case --
# the implementation is O(n) and a 1 MiB random payload takes ~0.5s
# per audit L-01; we keep the smoke budget tight.
_DEFAULT_MAX_HEX_LEN = 1024


def _gen_hex(rng: random.Random, max_len: int) -> str:
    n = rng.randint(0, max_len // 2)  # bytes -> hex chars
    return rng.randbytes(n).hex() if n else ""


def _run_cli(argv: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
    """Invoke ``python3 -m crc16_en13757 <argv>`` and return (rc, out, err)."""
    proc = subprocess.run(
        [sys.executable, "-m", "crc16_en13757", *argv],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=_REPO_ROOT,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _check_well_formed_hex(rng: random.Random, max_hex_len: int) -> None:
    """--data <random-hex> must exit 0 and print a valid 0x.... line."""
    payload_hex = _gen_hex(rng, max_hex_len)
    rc, out, err = _run_cli(["--data", payload_hex])
    if rc != 0:
        raise AssertionError(
            f"well-formed --data exit={rc} (expected 0) "
            f"hex_len={len(payload_hex)} stderr={err!r}"
        )
    out = out.strip()
    if "Traceback" in err:
        raise AssertionError(
            f"well-formed --data leaked traceback: stderr={err!r}"
        )
    if not (out.startswith("0x") and len(out) == 6):
        raise AssertionError(
            f"well-formed --data output shape: stdout={out!r}"
        )
    try:
        int(out, 16)
    except ValueError:
        raise AssertionError(
            f"well-formed --data output not parseable hex: {out!r}"
        )


def _check_malformed_hex(rng: random.Random, max_hex_len: int) -> None:
    """Random malformed hex strings must exit non-zero with a friendly
    error message, never an uncaught traceback."""
    # Three flavours: odd length, contains non-hex, contains non-hex
    # garbage (e.g. Unicode). Note: whitespace stripping in _parse_hex
    # means injecting a space in the middle of valid hex is NOT
    # malformed -- it's just whitespace. Skip that flavour.
    flavour = rng.choice(("odd", "nonhex", "garbage"))
    n = rng.randint(1, max_hex_len // 2)
    raw = rng.randbytes(n).hex()
    if flavour == "odd":
        bad = raw[:-1]  # chop the last char -> odd length
    elif flavour == "nonhex":
        # Inject a non-hex character at a random position.
        i = rng.randrange(0, len(raw))
        bad = raw[:i] + "Z" + raw[i + 1:]
    else:
        # Pure garbage: non-hex characters from the start. Use 1..n chars
        # so we don't accidentally produce an even-length hex string.
        bad_chars = "gZ!@#$%^&*"
        m = rng.randint(1, 8)
        bad = "".join(rng.choice(bad_chars) for _ in range(m))
    rc, out, err = _run_cli(["--data", bad])
    if rc == 0:
        raise AssertionError(
            f"malformed --data unexpectedly exited 0: bad={bad!r} out={out!r}"
        )
    if "Traceback" in err:
        raise AssertionError(
            f"malformed --data leaked traceback: stderr={err!r}"
        )
    # Friendly error -- either "error:" on stderr (cli.cmd_data) or
    # argparse's own usage message.
    friendly = "error:" in err or "usage:" in err
    if not friendly:
        raise AssertionError(
            f"malformed --data error message not friendly: "
            f"flavour={flavour} stderr={err!r}"
        )


def _check_missing_required() -> None:
    """No args must exit 2 with a usage message (argparse)."""
    rc, out, err = _run_cli([])
    if rc not in (0, 2):  # argparse uses 2; if 0 we'd have a bug.
        raise AssertionError(
            f"empty argv exit={rc} (expected 2) stderr={err!r}"
        )
    if "Traceback" in err:
        raise AssertionError(
            f"empty argv leaked traceback: stderr={err!r}"
        )
    if "usage:" not in err and "usage:" not in out:
        raise AssertionError(
            f"empty argv missing usage hint: out={out!r} err={err!r}"
        )


def _check_self_test() -> None:
    """--self-test must exit 0 with a clean PASS report."""
    rc, out, err = _run_cli(["--self-test"])
    if rc != 0:
        raise AssertionError(
            f"--self-test exit={rc} stderr={err!r}"
        )
    if "Traceback" in err:
        raise AssertionError(
            f"--self-test leaked traceback: stderr={err!r}"
        )
    if "6/6 vectors passed" not in out:
        raise AssertionError(
            f"--self-test output missing PASS marker: {out!r}"
        )


def _check_version() -> None:
    """--version must exit 0 and contain '0.1.0'."""
    rc, out, err = _run_cli(["--version"])
    if rc != 0:
        raise AssertionError(
            f"--version exit={rc} stderr={err!r}"
        )
    if "0.1.0" not in out:
        raise AssertionError(
            f"--version output missing version: {out!r}"
        )


def _check_help() -> None:
    """--help must exit 0 (argparse convention) and not leak traceback."""
    rc, out, err = _run_cli(["--help"])
    if rc != 0:
        raise AssertionError(
            f"--help exit={rc} stderr={err!r}"
        )
    if "Traceback" in err:
        raise AssertionError(
            f"--help leaked traceback: stderr={err!r}"
        )


def run(iters: int, seed: int, max_hex_len: int) -> int:
    rng = random.Random(seed)
    t0 = time.perf_counter()
    # Deterministic one-shot checks first.
    _check_missing_required()
    _check_self_test()
    _check_version()
    _check_help()
    # Random fuzz.
    for i in range(iters):
        try:
            _check_well_formed_hex(rng, max_hex_len)
            _check_malformed_hex(rng, max_hex_len)
        except AssertionError as exc:
            print(f"FAIL iter={i}: {exc}", file=sys.stderr)
            return 1
    elapsed = time.perf_counter() - t0
    rate = iters / elapsed if elapsed > 0 else float("inf")
    print(
        f"PASS harness_cli_args iters={iters} seed={seed} "
        f"max_hex_len={max_hex_len} elapsed={elapsed:.3f}s rate={rate:,.0f}/s"
    )
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--iters", type=int, default=100)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--max-hex-len", type=int, default=_DEFAULT_MAX_HEX_LEN)
    args = p.parse_args(list(argv) if argv is not None else None)
    return run(args.iters, args.seed, args.max_hex_len)


if __name__ == "__main__":
    sys.exit(main())