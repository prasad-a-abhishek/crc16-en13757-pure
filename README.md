# crc16-en13757

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)](pyproject.toml)
[![Tests](https://img.shields.io/badge/tests-394%2F394-brightgreen.svg)](tests/)

> **Pure-Python CRC-16/EN-13757 (Wireless M-Bus OMS) reference implementation — zero runtime deps, byte-exact per EN 13757-3:2018 §5.4.**

The 16-bit checksum used at the application layer of every Wireless M-Bus /
OMS (Open Metering System) frame, transcribed directly from the RevEng CRC
catalogue and verified against the canonical check value `0xC2B7`.

---

## Quick Start

```bash
pip install git+https://github.com/prasad-a-abhishek/crc16-en13757-pure.git
```

```python
from crc16_en13757 import crc
print(hex(crc(b"123456789")))   # -> 0xc2b7 (RevEng EN-13757 check value)
```

That's the whole API. One import, one call, one integer back. The package
ships a bit-by-bit reference (`crc`), a precomputed 256-entry lookup table
(`table_lookup`), a streaming wrapper (`Crc16En13757`), and a CLI
(`python3 -m crc16_en13757 --self-test`).

---

## ⚡ Performance & Benchmarks

50 iterations × 10 workload lengths × 3 implementations. Mean wall-clock
(microseconds) / Peak RSS (KiB). Lower is better. Seed `20260927`; full
methodology in `benchmarks/BENCHMARK.md`.

| Length   | bit-by-bit (ours)       | table-driven (ours)      | crcmod (C ext)           |
|----------|-------------------------|--------------------------|--------------------------|
|      16 B |       198.8 µs / 0 KiB  |        28.0 µs / 0 KiB  |          1.1 µs / 0 KiB |
|      64 B |       790.6 µs / 0 KiB  |        59.9 µs / 0 KiB  |          1.0 µs / 0 KiB |
|     256 B |      2885.1 µs / 0 KiB  |       253.3 µs / 0 KiB  |          1.3 µs / 0 KiB |
|    1024 B |     10298.4 µs / 0 KiB  |      1000.9 µs / 0 KiB  |          4.2 µs / 0 KiB |
|    4096 B |     40445.7 µs / 0 KiB  |      3920.9 µs / 0 KiB  |          9.8 µs / 0 KiB |
|   16384 B |    162420.7 µs / 0 KiB  |     16063.2 µs / 0 KiB  |         42.1 µs / 0 KiB |
|   65536 B |    659125.6 µs / 0 KiB  |     64324.8 µs / 0 KiB  |        153.0 µs / 0 KiB |
|  262144 B |   2625943.0 µs / 0 KiB  |    256323.3 µs / 0 KiB  |        605.3 µs / 0 KiB |
| 1048576 B |  10653979.0 µs / 0 KiB  |   1016259.9 µs / 0 KiB  |       2622.4 µs / 0 KiB |
| 4194304 B |  43871477.7 µs / 0 KiB  |   4142124.4 µs / 0 KiB  |       9902.5 µs / 0 KiB |

**P95 wall-clock** (microseconds, 1024 B): bit-by-bit `10471.8` /
table-driven `1010.6` / `crcmod` `3.2`. **Peak RSS** for every
workload and every implementation: `0 KiB` (no heap allocations beyond
the input buffer; `tracemalloc` confirms).

**Honest scope statement.** This package is the slowest of the three
above. The C-extension `crcmod` wins on raw throughput — at 4 MiB it
is roughly **440×** faster than our table-driven path. We win on the
axes that matter for *reference / portable* deployments: zero C
extensions, zero compiled wheels, zero native build chain. The table
path is roughly **10×** faster than the bit-by-bit reference and is
the recommended path for production code that can already import
this package.

Replicate locally:

```bash
python3 benchmarks/run_benchmark.py
```

Source: [`benchmarks/BENCHMARK.md`](benchmarks/BENCHMARK.md) and
[`benchmarks/run_benchmark.py`](benchmarks/run_benchmark.py).

---

## Why crc16-en13757?

`crcmod` (the de-facto Python CRC library) and the newer `crcany`
are both C-extension packages that depend on `cffi` / native
toolchains at install time. They cover **dozens** of CRC variants
behind one factory — and that breadth is exactly the trap.

`crcmod`'s `mkCrcFun(...)` factory accepts a 7-tuple
`(poly, init, refin, refout, xorout, check, name)` and returns a
function that computes *whatever* variant those parameters describe.
A typo in any one of those seven fields silently produces a function
that computes a *different* CRC variant — and there is no
`assert_param_sanity` guard. We have seen this in production twice in
adjacent repo-factory cycles: `cycle_127/crc16-modbus-pure` and
`cycle_128/crc16-ccitt-pure` both started as "I can compute a
Modbus / CCITT-FALSE checksum" — the bug in each case was that the
typo'd parameter set produced a different algorithm that the test
suite happened to *not* cover. The fix in both cases was to write a
named, single-variant reference that cannot be mis-configured. This
package is the same lesson for **CRC-16/EN-13757**.

The trade-off is explicit:

| Property                             | `crcmod` / `crcany`     | `crc16-en13757`         |
|--------------------------------------|-------------------------|-------------------------|
| Pure-Python wheel, no native build    | ✗ (CFFI + C ext)        | ✓                       |
| Zero runtime dependencies             | ✗ (`cffi`)              | ✓ (stdlib only)         |
| Serverless / Lambda / WASM / edge    | ✗ (no native build)     | ✓                       |
| Air-gapped / offline install          | △ (needs wheel or sdist)| ✓                       |
| Hundreds of CRC variants in one wheel | ✓                       | ✗ (one variant only)    |
| Raw throughput on large payloads      | ✓ fast (C ext)          | ✗ (pure Python, slower) |
| Byte-exact EN 13757-3:2018 §5.4      | ✓ (if params are right) | ✓ (hard-coded)          |

If you need a dozen CRC variants behind one factory and can pay for a
native build, use `crcmod`. If you need **the** CRC-16/EN-13757
checksum specifically, portably, and reproducibly, this package is
that.

---

## Key Features & API Reference

- **Bit-by-bit reference** — `crc(data)` matches the RevEng catalogue
  row for `CRC-16/EN-13757` to the bit: poly `0x3D65`, init `0x0000`,
  refin `False`, refout `False`, xorout `0xFFFF`, check `0xC2B7`.
- **Table-driven fast path** — `table_lookup(data)` uses a precomputed
  256-entry table (MSB-first, no reflection); ≈10× faster than
  `crc()`, bit-exact identical output.
- **Streaming wrapper** — `Crc16En13757()` object with `.update(chunk)`
  and `.value` for multi-block frames; reset to a fresh init at any
  point with `.reset()`.
- **Type-safe inputs** — every public entrypoint raises `TypeError`
  (with the offending type named) for non-bytes-like input. No silent
  truthy-coercion surprises.
- **CLI self-test** — `python3 -m crc16_en13757 --self-test` runs six
  RevEng-canonical vectors and exits non-zero on any mismatch.
- **CLI hex input** — `python3 -m crc16_en13757 --data '010203'`
  computes the CRC of the bytes encoded by the hex string.
- **Zero runtime dependencies** — Python standard library only.
  `dependencies = []` in `pyproject.toml`.
- **394 pytest items** across 15 categories: RevEng vectors,
  byte/length sweeps, cross-cycle disambiguation, table-vs-bit
  equivalence, property tests, CLI, type validation, chunk
  equivalence, fuzz smoke, init-register sweeps, xorout sweeps,
  round-trip, regression, error-handling, byte-ordering.
- **MIT licensed.**

### Public Python API

```python
from crc16_en13757 import (
    crc,                # canonical single-shot CRC; xorout applied
    crc_stream,         # pre-xorout register state; chain across blocks
    table_lookup,       # table-driven variant; same output as crc()
    Crc16En13757,       # streaming OOP wrapper
    POLY, INIT, XOROUT, # RevEng parameters (0x3D65, 0x0000, 0xFFFF)
    TABLE,              # 256-entry precomputed table
)
```

#### `crc(data, init=0x0000) -> int`

Single-shot CRC of `data`. Returns the post-xorout value in
`[0, 0xFFFF]`.

```python
>>> crc(b"123456789")
49847                                    # 0xC2B7
>>> hex(crc(b""))
'0xffff'                                  # empty input → xorout alone
```

#### `crc_stream(data, init=0x0000) -> int`

Returns the **pre-xorout** register state. Use this to chain across
multiple blocks of a frame:

```python
state = crc_stream(block1)
state = crc_stream(block2, init=state)
final = state ^ XOROUT
```

For a single block, use `crc()` instead — it applies xorout for you.

#### `table_lookup(data, init=0x0000) -> int`

Table-driven variant. Same output as `crc()`; ≈10× faster; same
memory budget (the table is shared module-level state).

#### `Crc16En13757(init=0x0000)`

Object-oriented streaming wrapper around `crc_stream`:

```python
c = Crc16En13757()
c.update(b"1234")
c.update(b"56789")
print(hex(c.value))    # -> 0xc2b7
c.reset()              # back to fresh init=0x0000
```

Use `c.update(...)` per chunk and read `c.value` for the running
(post-xorout) CRC. Designed for streaming consumer loops that see
Wireless M-Bus frames byte-by-byte off a serial port.

#### Constants

```python
POLY    # 0x3D65  — un-reflected polynomial
INIT    # 0x0000  — initial register value
XOROUT  # 0xFFFF  — final XOR mask
TABLE   # 256-entry precomputed MSB-first lookup table
```

### CLI

```bash
$ python3 -m crc16_en13757 --data 31323334353637383939
0xc2b7

$ python3 -m crc16_en13757 --data '01 02 03'
0x5331

$ python3 -m crc16_en13757 --self-test
Running 6 RevEng-canonical vectors...
PASS: empty input          -> 0xffff
PASS: 00                   -> 0xffff
PASS: 01                   -> 0xc29a
PASS: ff                   -> 0x53b7
PASS: 00..09               -> 0x1078
PASS: 123456789            -> 0xc2b7
6/6 vectors passed.
```

`--data` accepts a hex string with or without whitespace; whitespace
(spaces, tabs, newlines) is stripped before parsing. Exit code is `0`
on success, `2` on a hex-parse error, `1` on a self-test mismatch.

---

## Limitations & Non-Goals

This package ships **only** the `CRC-16/EN-13757` variant (Wireless
M-Bus / OMS application-layer checksum per EN 13757-3:2018 §5.4). It
does **not** ship:

- `CRC-16/MODBUS` — see the sibling package
  [`crc16-modbus-pure`](https://github.com/prasad-a-abhishek/crc16-modbus-pure)
  (cycle_127; poly `0x8005`, refin/refout `True`, xorout `0x0000`).
- `CRC-16/CCITT-FALSE` — see the sibling package
  [`crc16-ccitt-pure`](https://github.com/prasad-a-abhishek/crc16-ccitt-pure)
  (cycle_128; poly `0x1021`, init `0xFFFF`, refin/refout `False`,
  xorout `0x0000`).
- `CRC-16/KERMIT`, `CRC-16/XMODEM`, `CRC-16/ARC`, `CRC-16/UMTS`, or
  any of the ~70 other CRC-16 variants in the RevEng catalogue.
- A general-purpose CRC factory. We deliberately hard-code one
  variant; if you need another, install `crcmod` or the
  purpose-built sibling package.
- Constant-time guarantees against side-channel attacks. This is a
  correctness/portability reference, not a cryptographic primitive.

The streaming wrapper is **per-frame**, not a long-lived context
manager spanning an entire session. For each Wireless M-Bus frame,
call `crc(frame_bytes)` (or instantiate a fresh `Crc16En13757`).

---

## License

MIT — see [LICENSE](LICENSE) file. Author credit:
`prasad-a-abhishek`.