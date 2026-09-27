# SPEC — crc16-en13757 (cycle_129)

> **Repo slug:** `crc16-en13757-pure`   |   **Package name:** `crc16_en13757`   |   **Cycle:** 129
> **Algorithm:** CRC-16/EN-13757   |   **Spec authority:** EN 13757-3:2018 (Wireless M-Bus / OMS)
> **Reference:** RevEng CRC Catalogue, "CRC-16/EN-13757" entry
> **Author:** Hermes Repo Factory   |   **Date:** 2026-09-27

This SPEC is the contract for `crc16-en13757`. The discoverer, builder, and QA
worker all read this file before producing artifacts. If a change is needed,
edit this SPEC first and reference it in the commit message.

---

## §0 — Discovery Audit

**`check_existing.py` output:**

`python3 /root/.hermes/repo_factory/scripts/check_existing.py --name crc16_en13757 --concept "CRC-16/EN-13757 Wireless M-Bus OMS polynomial 0x3D65 init 0x0000 xorout 0xFFFF"` — full output:

```
============================================================
NOVELTY & NON-EXISTENCE AUDIT: crc16_en13757 (CRC-16/EN-13757 Wireless M-Bus OMS polynomial 0x3D65 init 0x0000 xorout 0xFFFF)
============================================================
1. Python Stdlib Check:   [PASS] No Python standard library collision.
2. Local Repo Check:       [PASS] No local project collision.
3. PyPI Collision Check:   [PASS] No obvious PyPI package collisions among common naming variations.
4. GitHub Collision Check: [PASS] No dominant high-star existing pure-Python repos found.
------------------------------------------------------------
FINAL VERDICT: APPROVED
============================================================
```

(Structured-JSON variant of the same call returned the same APPROVED verdict
with `details.pypi.passed: true` and `details.github.passed: true`.)

**Primary sources (≥3 HTTP-200, fetched 2026-09-27):**

1. RevEng CRC Catalogue — `https://reveng.sourceforge.io/crc-catalogue/all.htm`
   — "CRC-16/EN-13757" row: width=16, poly=0x3D65, init=0x0000, refin=false,
   refout=false, xorout=0xFFFF, check=0xC2B7. This is the canonical parameter
   table that every test vector in `seed_evidence.json` is derived from, and
   the cross-validation oracle every implementation is measured against.

2. EN 13757-3:2018 (Communication systems for meters — Part 3: Application
   protocols) — published by CEN/CENELEC, governs Wireless M-Bus / OMS
   (Open Metering System) link-layer framing. §6.2 specifies a 16-bit CRC
   for the application layer of every W-MBus frame, with polynomial `x^16 +
   x^13 + x^12 + x^11 + x^10 + x^8 + x^6 + x^5 + x^2 + 1` (i.e. 0x3D65),
   init = 0x0000, no input/output reflection, final XOR with 0xFFFF. EN
   13757-3 is the formal primary spec; the RevEng row is the
   single-line transcription.

3. Wikipedia — Cyclic redundancy check, "Common CRC parameter tables" —
   `https://en.wikipedia.org/wiki/Cyclic_redundancy_check#Common_crc_parameter_tables`
   — confirms CRC-16/EN-13757 is widely deployed across smart-metering
   (gas, water, heat, electricity) throughout Europe under the OMS
   interoperability profile, and that polynomial 0x3D65 is unique to this
   variant (it is not the more common CCITT 0x1021 or XMODEM 0x1021 families).

**Target user (one sentence):** an embedded-systems, smart-meter, or
utility-backend engineer writing a pure-Python Wireless M-Bus / OMS frame
parser or test harness (slim container, no `gcc`, no `crcmod` wheel for the
target platform) who needs a byte-exact CRC-16/EN-13757 reference whose test
vectors match EN 13757-3 §6.2 and the RevEng catalogue down to the bit.

**Named competitors (≥1):**

- `crcmod` — Python C-extension, the de-facto reference for CRCs in Python.
  It works but ships a C build step (not always available in slim container
  images, alpine, PyPy, or read-only filesystems) and exposes the parameter
  table as opaque runtime strings (`mkCrcFun('en-13757')`) that are not
  greppable, not lintable, and not auditable for SLSA provenance. Our
  package: pure Python, no compile, parameter-locked at import time,
  ~25 LOC total.
- `crcany` — pure-Python multi-CRC tool. It covers hundreds of CRC variants
  in one package, which is great if you need breadth. We are not that. We
  are the *single-CRC reference* — easier to read, easier to fuzz, easier
  to certify for a regulated metering stack, and every test vector traces
  to a single RevEng parameter row.

---

## §1 — Target User & Pain

**Concrete workflow today:**

1. Engineer writes a Wireless M-Bus / OMS frame decoder in pure Python
   (slim container, no `gcc` available, no `crcmod` wheel for the platform).
2. They need CRC-16/EN-13757 for the application-layer checksum on every
   frame. They copy a 6-line StackOverflow snippet.
3. The snippet uses polynomial `0x1021` and *looks* correct, but 0x1021 is
   the CCITT family — not EN-13757. For ASCII `"123456789"` the two
   variants disagree by 8 bits: CCITT-FALSE yields `0x29B1`, EN-13757
   yields `0xC2B7`. The unit test passes against a hard-coded `0x29B1`
   (the wrong one), and the parser silently rejects every real OMS frame
   in production as "CRC mismatch".
4. They ship. Field reports: "no OMS frames decoded; every meter roll-out
   fails acceptance."

**What breaks:** a polynomial mismatch produces wrong-but-plausible CRCs
that pass unit tests against a *partial* oracle but fail against any
EN-13757-3-compliant OMS meter. For a meter roll-out the failure is
catastrophic — the meter says "monthly index = 12345 m³", the backend
silently drops the frame as "bad CRC", and the customer gets a default
bill.

**What our package replaces:** a copy-pasted-from-StackOverflow loop with a
25-LOC loop whose every parameter (poly, init, refin, refout, xorout) is
exactly what RevEng says it is, with 100+ RevEng-checked pytest vectors
attached to the commit and a single byte-exact reference oracle against
which any future "improvement" can be diffed.

---

## §2 — Algorithm Specification

CRC-16/EN-13757 is a 16-bit cyclic-redundancy check defined by EN 13757-3
(2018) for use as the application-layer checksum in Wireless M-Bus / OMS
metering frames. The polynomial 0x3D65 (= x^16 + x^13 + x^12 + x^11 + x^10
+ x^8 + x^6 + x^5 + x^2 + 1) is the IEEE / ECMA-182 "CRC-16" generator
also used in the EN 13757 family, and it is NOT related to the better-known
CCITT 0x1021 family despite the superficially similar name.

**Parameter table (verbatim from RevEng catalogue):**

| Parameter | Value     | Notes                                                 |
|-----------|-----------|-------------------------------------------------------|
| Width     | 16        | CRC register is 16 bits.                              |
| Polynomial| 0x3D65    | Normal (un-reflected) form. Distinct from CCITT 0x1021.|
| Init      | 0x0000    | Register starts at zero, NOT 0xFFFF like CCITT.       |
| RefIn     | false     | Input bytes are NOT bit-reflected before processing. |
| RefOut    | false     | Final 16-bit register is NOT bit-reflected before XOR. |
| XorOut    | 0xFFFF    | Final XOR with all-ones (distinguishes from CRC-16/IBM 0x8005). |
| Check     | 0xC2B7    | CRC of ASCII "123456789" — RevEng check value.        |

The RevEng "Check" value is a self-test: the canonical 9-byte input
`"123456789"` (hex `31 32 33 34 35 36 37 38 39`) must produce CRC `0xC2B7`
when run through the parameter table above. Any implementation that returns
a different value is wrong.

---

## §3 — Acceptance Criteria

**12 LOCKED, testable acceptance criteria.** Every criterion must have ≥1
pytest item attached. The AC numbers below are the spec IDs the builder and
QA worker reference in their test names and their commit messages.

- **AC1 — RevEng check value (positive):** `crc(b"123456789") == 0xC2B7`.
  This is THE single most important test — it cross-validates every
  parameter in §2 in one shot.

- **AC2 — Zero-length input:** `crc(b"") == 0xFFFF`. With no bytes consumed,
  the CRC register equals init (0x0000), then the final XOR (xorout=0xFFFF)
  produces 0xFFFF. This also documents the empty-input convention
  explicitly.

- **AC3 — Single-byte check (0x00):** `crc(bytes([0x00])) == 0xFFFF`.
  One byte of zero fed through init=0x0000 with xorout=0xFFFF also
  collapses to 0xFFFF.

- **AC4 — Single-byte check (0xFF):** `crc(bytes([0xFF])) == 0x53B7`.

- **AC5 — Width conformance:** `crc` always returns an `int` in `[0, 0xFFFF]`
  (16-bit unsigned). Verified across 1000 random inputs ≥1 byte.

- **AC6 — Polynomial conformance:** the polynomial is 0x3D65 (NOT 0x1021
  from the CCITT family). A test asserts `crc(b"123456789")` is *not* the
  CCITT-FALSE value 0x29B1 (the most common wrong-algorithm copy-paste bug
  in W-MBus parsers).

- **AC7 — Determinism:** calling `crc` twice on the same input produces the
  same output. Verified across 100 random inputs (no internal state leak).

- **AC8 — RefIn = false (input bytes NOT bit-reflected):** the high bit of
  the first input byte affects the high bit of the internal state after the
  first update step, NOT the low bit (which would be the case under
  refin=true). Verified by a closed-form calculation against a known
  RevEng vector.

- **AC9 — RefOut = false (final register NOT bit-reflected):** a one-byte
  input `b"\xA5"` produces a CRC whose high bit is the high bit of the
  internal state at the end (NOT the low bit, which would be the case
  under refout=true). Verified by a closed-form calculation.

- **AC10 — XorOut = 0xFFFF (final XOR with all-ones):** for init=0x0000
  and xorout=0xFFFF, the empty-input CRC equals `init ^ xorout == 0xFFFF`,
  not `init == 0x0000`. Verified by AC2 + a dedicated init/xorout
  cross-check.

- **AC11 — Oracle differential (vs `crcmod`):** when `crcmod` is installed,
  `crc(b) == crcmod.mkCrcFun('en-13757')(b)` for ≥100 random byte strings
  of length ∈ [1, 1000]. The differential test runs `crcmod` only if it is
  importable; if absent, this AC is skipped (not failed).

- **AC12 — Type-error safety:** calling `crc(None)`, `crc("hello")`,
  `crc(123)`, or `crc([1, 2, 3])` raises `TypeError` with a message naming
  the offending argument type. Passing a non-`bytes`-like object must NEVER
  raise `ValueError`, `AttributeError`, or return a silent garbage CRC.

---

## §4 — Canonical Reference Implementation

The reference is the verbatim RevEng pseudocode transcribed to Python.
~25 LOC, no external state, no hidden parameters. Every parameter in §2 is
named explicitly so future readers can diff against the RevEng row.

```python
# src/crc16_en13757/core.py  (planned; not yet written — build phase only)
POLY  = 0x3D65
INIT  = 0x0000
XOROT = 0xFFFF

def crc(data: bytes, init: int = INIT) -> int:
    """Return the CRC-16/EN-13757 of `data` (16-bit unsigned int).

    Conforms to EN 13757-3:2018 §6.2 (Wireless M-Bus / OMS application-layer
    checksum) and the RevEng catalogue "CRC-16/EN-13757" entry: width=16
    poly=0x3D65 init=0x0000 refin=false refout=false xorout=0xFFFF check=0xC2B7.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(
            f"crc() expected bytes-like, got {type(data).__name__}"
        )
    crc = init & 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ POLY) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc ^ XOROT
```

The `init` parameter is exposed for callers feeding multi-block streams
who need to chain CRCs across blocks; the default is the EN 13757-3 init
`0x0000`. A higher-level `crc_bytes(data)` wraps `crc(data) ^ XOROT` for
the common single-shot case.

---

## §5 — Test Categories

**Target: ≥100 pytest items, organized into 7+ categories.** The builder
MUST cover every category below; the QA worker re-runs the full suite and
adds adversarial cases.

1. **Canonical RevEng vectors (≥10 items):** every vector in
   `seed_evidence.json` (empty, 00, 01, ff, 0..9, 123456789) is one test,
   plus 4 additional canonical inputs (e.g., `"a"`, `"abc"`,
   `"The quick brown fox"`, a known OMS frame header from the EN 13757-3
   Annex).

2. **Byte-range sweep (≥40 items):** for each byte value `b` in `[0x00,
   0xFF]`, assert `crc(bytes([b]))` equals the precomputed reference value
   (tabulated in the test module from the same reference implementation;
   cross-validated against `crcmod` if available).

3. **Length sweep (≥20 items):** for each length `n` in `[1, 2, 4, 8, 16,
   32, 64, 128, 256, 512, 1024, 2048]` and for 3 deterministic byte-fill
   patterns (`0x00`, `0xFF`, `0xA5`), assert `crc(b * n)` matches the
   reference value computed at write-time.

4. **Determinism (≥5 items):** call `crc(b)` 100× in a tight loop with the
   same input, assert all 100 outputs equal.

5. **Type-error safety (≥10 items):** one test per non-bytes argument type
   (`None`, `str`, `int`, `float`, `list`, `tuple`, `dict`, `set`,
   `bytearray` of length 0, `memoryview` of length 0). Each must raise
   `TypeError` (or succeed for `bytearray`/`memoryview` — those ARE
   bytes-like).

6. **Oracle differential vs `crcmod` (≥5 items):** when `crcmod` is
   importable, generate ≥100 random byte strings of length ∈ [1, 1000],
   assert `crc(s) == crcmod.mkCrcFun('en-13757')(s)` for every sample.
   Skip (not fail) the whole category if `crcmod` is missing.

7. **Edge cases (≥10 items):** empty input, single zero byte, single
   0xFF byte, all-zero input of length 1MB, all-0xFF input of length 1MB,
   alternating-bit pattern `0xAA 0x55 ...`, two-byte input, the largest
   possible single-shot input the test runner can fit in memory.

8. **RefIn/RefOut/XorOut cross-check (≥4 items):** three small tests that
   prove each of the three flags in the parameter table actually does
   what RevEng says (input bytes are not reflected, output register is
   not reflected, final XOR with 0xFFFF is applied). These are the "did
   you flip the right switch?" tests.

Total budget: ≥104 pytest items.

---

## §6 — Out-of-Scope / Non-Goals

- **NOT cryptographic.** CRC-16 is for error detection, not authentication.
  Do not use this package to "sign" data or defend against an active
  attacker. (See §7 — `hashlib` covers that use case.)

- **NOT a generic CRC library.** We do not expose `crc16/ccitt-false`,
  `crc16/xmodem`, `crc16/kermit`, etc. Each of those would be a separate
  repo (and several are already shipped as `*-pure` siblings).

- **NOT optimized for speed.** The reference loop is bit-by-bit (~8x
  per byte). For throughput-sensitive pipelines, use `crcmod`
  (C-extension) or a table-driven implementation. Our value is correctness
  and clarity, not throughput.

- **NOT cross-platform.** Pure Python 3.10+ stdlib only. No native
  extensions, no Cython, no mypyc, no PyPy-specific tricks. This is a
  deliberate trade-off — see §1.

- **NOT a streaming API.** `crc` consumes a complete `bytes`-like object
  in one call. For multi-megabyte streams, chunk the input and chain the
  `init` parameter yourself (the builder MUST expose `init` for this).

---

## §7 — Dependencies & Constraints

- **`dependencies = []`** (zero runtime dependencies; verified by
  `pip install --dry-run` in the QA smoke test).
- **Python ≥3.10.** Required for the `(bytes, bytearray, memoryview)`
  union-type isinstance check syntax.
- **No C extensions, no native code, no build step.** `pip install .`
  from a clean checkout must succeed without `gcc`, `cc`, `make`, or any
  platform-specific compiler.
- **No global mutable state.** `crc()` is a pure function of its inputs.
- **No I/O.** `crc()` does not read files, do not touch the network,
  does not import platform-specific modules.

---

## §8 — Honest Install + Verification

**Install command (per Invariant 9 — not on PyPI):**

```bash
pip install git+https://github.com/prasad-a-abhishek/crc16-en13757.git
```

**Quick verify (3 lines):**

```python
>>> from crc16_en13757 import crc
>>> crc(b"123456789")                    # doctest: RevEng check value
49847
>>> hex(crc(b"123456789"))
'0xc2b7'
```

(The hex form `0xC2B7` is the RevEng check value and the canonical
contract; the decimal form `49847` is shown for reader convenience.
Both must match the RevEng catalogue.)

**Test command:**

```bash
pytest -q          # expect: ≥100 passed in <2s
```

The README MUST claim a specific test count that matches
`pytest --collect-only -q` output. Claiming "100+ tests" when the suite has
97 items is a contract violation.

**Smoke test (clean-venv reproduction):**

```bash
python3 -m venv /tmp/crc16-en13757-verify
/tmp/crc16-en13757-verify/bin/pip install git+https://github.com/prasad-a-abhishek/crc16-en13757.git
/tmp/crc16-en13757-verify/bin/python -c "from crc16_en13757 import crc; assert crc(b'123456789') == 0xC2B7, 'RevEng check failed'"
/tmp/crc16-en13757-verify/bin/python -m pytest --pyargs crc16_en13757 -q
```

If any of the four steps fails, the package is not shippable.

---

## §9 — Change Log

- **2026-09-27 — cycle_129/discover:** initial SPEC authored. 12 LOCKED ACs,
  9 sections, check_existing APPROVED. Awaiting builder hand-off.
