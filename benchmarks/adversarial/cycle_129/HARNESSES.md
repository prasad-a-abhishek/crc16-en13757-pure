# cycle_129 / Adversary / Fuzzing Harnesses

> Companion deliverable to `VULN_AUDIT.md` (card 01) for the
> `@repo-adversary` workstream on `crc16-en13757-pure`. These harnesses
> are the second card of the 5-card Invariant 26 workstream — fuzzing
> harnesses covering ≥3 of the documented attack surfaces.

## 1. Scope & Methodology

This package implements **CRC-16/EN-13757** (Wireless M-Bus / OMS):
poly=0x3D65, init=0x0000, xorout=0xFFFF, MSB-first, no reflection,
RevEng canonical check 0xC2B7. The implementation is ~80 LOC of pure
Python stdlib — there is no `unsafe`, no FFI, no allocator
manipulation. The realistic adversarial surface is therefore:

1. **Type confusion** at the public API boundary (`Invariant 21`).
2. **CLI argv injection** (malformed `--data`, missing args, etc.).
3. **Reference-vs-implementation divergence** in the lookup table.
4. **Streaming-chain equivalence** (`Crc16En13757.update()` must
   equal `crc(concat(pieces))` — the Invariant 14 property).
5. **Cross-package parameter independence** (must NOT collide with
   cycle_127 modbus at 0x4B37 or cycle_128 ccitt at 0x29B1).

The harnesses below use **stdlib `random` + try/except**, not Atheris,
because:

* Atheris requires CPython with `--enable-coverage` instrumentation.
* The stdlib pattern is fully reproducible (deterministic seed) and
  re-playable (capture the failing seed + iter to regenerate).
* No instrumentation overhead means more useful iterations per
  second on the bytes-fast-path.

ASan/UBSan are not configured because the test runtime is stock
CPython 3.11.15 (no compiler tooling available in the worker's
container). The invariants exercised here are at the
**interface / contract level** — not at the memory level — and the
audit at card 01 already confirmed the implementation is C-extension
free.

### Smoke run

```
$ for h in harness_*.py; do python3 "$h" --iters 100 --seed 42; done
PASS harness_cli_args iters=100 seed=42 max_hex_len=1024 elapsed=3.401s rate=29/s
PASS harness_crc_engine_streaming iters=100 seed=42 max_len=65536 max_chunks=32 elapsed=10.087s rate=10/s
PASS harness_crc_main iters=100 seed=42 max_len=16384 elapsed=2.039s rate=49/s
PASS harness_cross_cycle_oracle iters=100 seed=42 corpus=101 en=0xc2b7 modbus=0x4b37 ccitt=stub_unavailable elapsed=0.009s
PASS harness_table_integrity iters=100 seed=42 table_len=256 elapsed=0.038s
PASS harness_type_errors iters=100 seed=42 canonical=20 surfaces=4 elapsed=0.000s rate=308,444/s
```

All 6 harnesses exit 0 on the smoke configuration.

---

## 2. Surface coverage matrix

| # | Harness | Public surface | Invariant exercised | Risk if violated |
|---|---------|----------------|---------------------|------------------|
| 1 | `harness_crc_main.py` | `crc16_en13757.crc(data)` | TypeError on non-bytes-like; view-equivalence across `bytes`/`bytearray`/`memoryview`; mutation isolation; output range `[0, 0xFFFF]` | Silent garbage CRC; caller-pays bug |
| 2 | `harness_crc_engine_streaming.py` | `Crc16En13757` `.update()` / `.value` / `.reset()` | Single-shot equality; N-piece chain equality; reset round-trip; 1-byte-chunked all-zero | Streaming mismatch — frames checksummed wrong |
| 3 | `harness_table_integrity.py` | `crc16_en13757.TABLE`; `crc16_en13757._table.table_lookup` | Poly pin 0x3D65; shape (256-tuple of int[0,0xFFFF]); byte-uniqueness; reference-table equality; table-driven ↔ bit-by-bit equivalence | Wrong polynomial silently computed |
| 4 | `harness_cli_args.py` | `python3 -m crc16_en13757 --data/--self-test/--version/--help` | Well-formed hex exits 0; malformed hex exits 2; never leaks `Traceback`; `--self-test` prints `6/6 vectors passed`; `--version` contains `0.1.0` | Uncaught traceback in production; `--self-test` regresses |
| 5 | `harness_type_errors.py` | `crc`, `crc_stream`, `table_lookup`, `Crc16En13757.update()` | All four entry points raise `TypeError` (NOT `ValueError`, NOT `AttributeError`) for 20 canonical bad inputs + randomized fuzz | `Invariant 21` violation: uncaught `AttributeError` from internal iteration |
| 6 | `harness_cross_cycle_oracle.py` | `crc` ↔ `crc16_modbus_pure.crc` ↔ `crc16_ccitt.crc16` | `crc(b'123456789')` = 0xC2B7; `crc16_modbus_pure.crc(b'123456789')` = 0x4B37; randomized corpus produces no collisions; ccitt gracefully skipped if `stub_unavailable` | Polynomial collapse — three packages produce identical CRCs |

---

## 3. Per-harness design

### 3.1 `harness_crc_main.py`

Targets the canonical single-shot `crc()` entry point. Four checks
run inside every iteration, each on an independently-randomized
payload:

* **Determinism** — calling `crc(p)` twice with the same `p` must
  return the same value (catches accidental PRNG drift).
* **View equivalence** — `crc(bytes(p)) == crc(bytearray(p)) ==
  crc(memoryview(p))`. Catches accidental implicit conversions that
  mutate one view but not the others.
* **Mutation isolation** — capturing `crc(ba)` and *then* mutating
  `ba` must not affect the previously-returned `int`. Confirms the
  return value is a plain `int`, not a memoryview into the caller's
  buffer.
* **Range** — every output must lie in `[0, 0xFFFF]`.

Default `--max-len` is 16 KiB so smoke runs finish in ~2s; pass
`--max-len 1048576` for the full 1 MiB sweep.

### 3.2 `harness_crc_engine_streaming.py`

Targets `Crc16En13757`. Four checks:

* **Single-shot equality** — feeding one piece of `len == N` bytes
  to `.update()` must produce the same CRC as `crc(piece)`.
* **Chaining equality** — feeding 1..32 pieces of randomized sizes
  (sum to N) must produce the same CRC as `crc(concat(pieces))`.
  This is THE property that makes `.update()` useful.
* **Reset round-trip** — calling `.reset()` and re-feeding the same
  data must reproduce the same value (and agree with a fresh
  `Crc16En13757()` instance fed the same data).
* **All-zero 1-byte-chunked** — feed 4 KiB of zero bytes in
  1-byte pieces; result must equal `crc(b"\x00"*4096)`.

### 3.3 `harness_table_integrity.py`

Targets the `_table.TABLE` constant and `table_lookup()`. Five
checks (deterministic, not affected by `--iters`):

* **Polynomial pin** — `core.POLY == 0x3D65`. Hard-coded as a
  second copy in the harness so a silent constant move is caught.
* **Shape** — `TABLE` is a `tuple` of exactly 256 `int`s in
  `[0, 0xFFFF]`.
* **Reference cross-check** — recompute the table from scratch
  inside the harness and assert every entry matches. The
  recomputation is a *standalone* function in the harness file —
  any code-level bug in the implementation cannot also affect the
  reference.
* **Byte uniqueness** — no two entries may be equal (a duplicate
  would prove the polynomial is over a degenerate quotient ring,
  impossible for a non-zero 16-bit poly).
* **Table-driven ↔ bit-by-bit** — for `--iters` random payloads,
  `table_lookup(p)` must equal `crc(p)`. Both implementations are
  deliberately independent code paths; any drift between them is a
  regression.

### 3.4 `harness_cli_args.py`

Targets `python3 -m crc16_en13757`. Five checks:

* **Deterministic checks** — empty argv (argparse exit 2 with
  usage hint), `--self-test` (exit 0, prints `6/6 vectors passed`),
  `--version` (exit 0, contains `0.1.0`), `--help` (exit 0).
* **Random fuzz (`--iters` × 2 per iteration)** —
  *Well-formed hex* must exit 0 with `0x....` on stdout. *Malformed
  hex* (odd length / non-hex char / pure garbage) must exit
  non-zero with `error:` or `usage:` on stderr, never with an
  uncaught `Traceback`.

NOTE: the task body listed `--input-file` as a CLI surface, but the
implementation exposes only `--data` / `--self-test` / `--version` /
`--help` (audit card 01 finding: surface_5_does_not_exist). The
harness covers the *actual* CLI surface.

### 3.5 `harness_type_errors.py`

Targets the Invariant 21 contract — "total over arbitrary input,
structured findings instead of uncaught `ValueError`/`TypeError`/
`AttributeError`". Four public surfaces × 20 canonical bad inputs
+ `--iters` random bad inputs.

* 20 canonical bad inputs: `None`, ints (incl. negative, large,
  NaN-via-float), strings (incl. UTF-8, embedded NUL), list/tuple
  of ints, dict, set, bare `object()`, lambda.
* 4 surfaces: `crc`, `crc_stream`, `table_lookup`,
  `Crc16En13757.update()`.

Every call must raise `TypeError` with a non-empty message. If a
surface ever regresses to letting a non-bytes-like iterate (and
subsequently raises `AttributeError` from inside `for byte in data:`),
this harness flags it.

### 3.6 `harness_cross_cycle_oracle.py` *(optional, included)*

Targets the differential-oracle property across the three sibling
CRC packages shipped in cycles 127, 128, and 129:

* `crc16_en13757.crc(b'123456789')` MUST == `0xC2B7`.
* `crc16_modbus_pure.crc(b'123456789')` MUST == `0x4B37`.
* `crc16_ccitt.crc16(b'123456789')` MUST == `0x29B1` IF the
  package exposes a callable CRC; otherwise recorded as
  `stub_unavailable` (the cycle_128 ship is a stub per the parent
  handoff).
* For a 101-payload random corpus (empty + 100 random bytes of
  varying length), no collision between any two packages.

---

## 4. How to run

From the repo root:

```bash
# Smoke (≈15 seconds total).
for h in benchmarks/adversarial/cycle_129/harness_*.py; do
    python3 "$h" --iters 100 --seed 42
done

# Full sweep (max-len bumped to 1 MiB on the main harness).
python3 benchmarks/adversarial/cycle_129/harness_crc_main.py --iters 1000 --seed 42 --max-len 1048576

# Reproduce a single harness with a specific seed (handy for
# capturing the seed if any harness ever fails).
python3 benchmarks/adversarial/cycle_129/harness_cross_cycle_oracle.py --seed 1234567890
```

Each harness exits `0` on no anomaly, `1` on the first failing
assertion (with `iter=N`, `check=NAME`, and the exact assertion text
on stderr). A failed harness is **always** re-playable by the seed
that produced it.

---

## 5. Expected invariants summary

For every smoke run with `--seed 42`, all six harnesses MUST exit 0
with the PASS summary line. Specifically:

* **`harness_crc_main.py`** — output line contains
  `PASS harness_crc_main iters=100 seed=42`.
* **`harness_crc_engine_streaming.py`** — output line contains
  `PASS harness_crc_engine_streaming iters=100 seed=42`.
* **`harness_table_integrity.py`** — output line contains
  `table_len=256` (TABLE has exactly 256 entries).
* **`harness_cli_args.py`** — output line contains
  `PASS harness_cli_args iters=100 seed=42`; no
  `Traceback` substring anywhere on stderr.
* **`harness_type_errors.py`** — output line contains
  `canonical=20 surfaces=4`.
* **`harness_cross_cycle_oracle.py`** — output line contains
  `en=0xc2b7 modbus=0x4b37`; ccitt status recorded
  (`ok` if cycle_128 is shipped, `stub_unavailable` if not).

A deviation from any of these in a clean run is a finding to be
captured in card 03 (seed corpus + execution) and card 04
(triage + minimize).

---

## 6. Limitations

* The harnesses do NOT exercise ASan/UBSan because the worker's
  container is stock CPython 3.11.15 without compiler tooling. For
  the byte-shuffling surface of a CRC implementation, interface-level
  fuzzing is the higher-value approach; memory-level bugs in pure
  Python are rare and would not show up in `random.randbytes` workloads.
* The cross-cycle oracle marks `crc16_ccitt` as `stub_unavailable`
  per the parent handoff; if cycle_128 ever ships a real CRC, this
  harness will auto-tighten its assertion and start failing on
  collisions.
* No coverage instrumentation — finding a *new* code path requires
  a future `--enable-coverage` build of CPython + Atheris (out of
  scope for this card).

---

**Card**: `cycle_129/adversary/02_harnesses` — VERDICT: PASS (6/6
harnesses clean smoke run, all 6 surfaces covered, all 4 documented
invariants exercised).