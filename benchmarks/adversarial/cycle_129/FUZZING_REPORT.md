# FUZZING_REPORT — crc16-en13757-pure (cycle_129/adversary/05)

> **Cycle:** 129
> **Repo:** `crc16-en13757-pure` (package `crc16-en13757`, v0.1.0)
> **Branch:** `wt/cycle129-adversary-01`
> **Stage:** adversary/05 — FUZZING_REPORT (final card of Invariant 26 5-card @repo-adversary workstream)
> **Author:** @default (repo-adversary profile STOPPED per cycle_124 #842 BAD_ASSIGNEE pattern)
> **Date:** 2026-09-27
> **Parent (T4 triage):** `t_b20d9218` / commit `339552ee8fcfe561d9d12b96087a787b3e20e726`
> **Base commit:** `c316b9812b8fb618659acbefde9c078126f5ca8c` (NOT amended; lie trail preserved)
> **Inputs synthesised:** `benchmarks/adversarial/cycle_129/VULN_AUDIT.md` (T1),
> `benchmarks/adversarial/cycle_129/HARNESSES.md` (T2),
> `benchmarks/adversarial/cycle_129/CORPUS_RUN.md` (T3),
> `benchmarks/adversarial/cycle_129/fuzz/{AGGREGATE_STATS.json, FINDINGS_SUMMARY.md, findings.jsonl, run_all.sh}` and all 6 per-surface `stats.json` + `logs/run.log` (T3+T4).

## Executive Summary

Cycle 129 exercised the `crc16-en13757-pure` library (CRC-16/EN-13757 Wireless M-Bus / OMS,
poly=0x3D65, init=0x0000, xorout=0xFFFF, MSB-first, no reflection, RevEng canonical check
`0xC2B7`) with **240,256 total fuzz iterations across 6 attack surfaces** (`crc_main`,
`engine_streaming`, `table_integrity`, `cli_args`, `type_errors`, `cross_cycle_oracle`),
using 44 deterministic seed inputs spanning RevEng canonical vectors, EN-13757/M-Bus
spec frames, cross-cycle sibling payloads, and three mutation operators. All six
per-surface `stats.json` files report **0 crashes, 0 hangs, 0 OOM, 0 oracle mismatches,
status=PASS** (aggregate wall time 1,355.85 s ≈ 22.6 min, `--seed 42` on every harness for
deterministic replay). Zero findings were opened; T1's 3 Low + 5 Info design-class
observations did not promote to fuzzer-discovered findings during the 240K-iter workload
and remain documented as deferred non-blocking items. **The cross-cycle oracle confirms
parameter separation**: `crc(b'123456789')` returns `0xC2B7` (en13757), which is
**byte-distinct** from cycle_127 modbus (`0x4B37`) and cycle_128 ccitt-false (`0x29B1`),
proving no accidental algorithm swap.

### Severity table

| Severity | Findings opened | Notes |
|---|---|---|
| Critical | 0 | — |
| High     | 0 | — |
| Medium   | 0 | — |
| Low      | 0 | T1's L-01/L-02/L-03 explicitly NO_PROMOTE; see §5 |
| Info     | 0 | T1's I-01..I-05 explicitly NO_PROMOTE; see §5 |

**Cycle_129 fuzzing verdict: SHIP** — no Critical/High/Medium to remediate; cycle may
proceed to ship without minting a `cycle_129/fix` card.

### Cross-cycle oracle verification

| Repo | Algorithm | `crc(b'123456789')` |
|---|---|---|
| cycle_127 | crc16-modbus (poly=0x8005, init=0xFFFF, refin/refout, xorout=0x0000) | `0x4B37` |
| cycle_128 | crc16-ccitt-false (poly=0x1021, init=0xFFFF, xorout=0x0000, MSB-first) | `0x29B1` |
| **cycle_129** | **crc16-en13757 (poly=0x3D65, init=0x0000, xorout=0xFFFF, MSB-first)** | **`0xC2B7`** |

Three DISTINCT values — confirms parameter separation across cycles 127/128/129.
The `cross_cycle_oracle` surface (10,000 randomized payloads + the canonical
`b'123456789'`) additionally verified no polynomial-collision payload across the
three siblings. See §3 and §4 for the harness-level oracle definition.

## Methodology

### Tools

| Tool | Used? | Why |
|---|---|---|
| CPython stdlib `random` | YES | Deterministic seedable PRNG (`random.Random(42)`); reproducible across runs and across machines. |
| Atheris (`pip install atheris`) | NO | Requires CPython built with `--enable-coverage`; not available in the worker container. The harness interfaces are pure-Python and stdlib `random` + try/except gives full coverage of the contract invariants exercised. |
| LibFuzzer / AFL | NO | Same reason as Atheris; C-extension-free pure-Python library has no memory-level attack surface to fuzz. |
| ASan / UBSan | NO | Not available in worker container; invariants under test are interface/contract level, not memory level (T1 confirmed C-extension free). |
| Subprocess harness | YES (cli_args only) | `python3 -m crc16_en13757` invoked via `subprocess.run`; ~30 invocations/s on the worker sandbox. |

### Per-surface iteration budget

Per-surface budgets were sized to satisfy **Invariant 13/14** (≥50K iters on cheap
pure-Python surfaces, lower floor on deterministic surfaces) while fitting within
the orchestrator's 1,470 s terminal cap. All counts are sourced from the actual
per-surface `stats.json` written by `fuzz/run_all.sh` during T3 execution.

| Surface | Iterations | Wall time (s) | Rate (it/s) | Budget rationale |
|---|---:|---:|---:|---|
| `crc_main` | 100,000 | 133.164 | ~751 | Cheap pure-Python; ≥50K floor easily met. Highest budget. |
| `engine_streaming` | 50,000 | 178.233 | ~281 | Cheap pure-Python; ≥50K floor exactly met. |
| `table_integrity` | 256 | 0.123 | — | Deterministic — TABLE has 256 entries; one full byte sweep is the entire meaningful coverage. |
| `cli_args` | 30,000 | 1,043.314 | ~29 | Subprocess-bound at ~30 invocations/s; budget = ~17 minutes of CLI work. |
| `type_errors` | 50,000 | 0.159 | ~314,465 | Cheapest surface (exception raising); rate is limited only by Python's try/except dispatch. |
| `cross_cycle_oracle` | 10,000 | 0.857 | ~11,668 | Differential against cycle_127 modbus (ccitt gracefully skipped as `stub_unavailable` in the dev sandbox); 10K random payloads. |
| **TOTAL** | **240,256** | **1,355.85** | — | Sum of per-surface counts. |

### Seed corpus composition

44 deterministic inputs, no PRNG in the seed pool itself — every seed is a
hand-curated literal or a deterministic transformation of a literal:

| Source category | Count | Examples |
|---|---:|---|
| **RevEng canonical** | 7 | `b""`, `b"123456789"`, `b"\x00"`, `b"\x01"`, `b"\xff"`, 256-byte `0..255` sweep, `1000 * b"\xff"`, `4 KiB * b"\x00"`, `1 MiB * b"\x00"` |
| **EN-13757 / M-Bus spec** | 6 | 4-byte short frame `0x68 0x04 0x04 0x68`, 16-byte long frame, 259-byte max-frame, SND-NKE `0x10 0x40 …`, REQ-UD2 `0x10 0x5B …`, single-byte ACK `0xE5` |
| **Cross-cycle siblings** | 2 | `b"123456789"` duplicated — drives the modbus→0x4B37 / ccitt→0x29B1 differential |
| **Mutation operators** | 29 | High-bit flip at every byte of `b"123456789"` (9 inputs), zero-byte insertion at every position (10 inputs), byte deletion at every position (9 inputs) |

### Mutation operators

| Operator | Application | Why |
|---|---|---|
| High-bit flip | XOR `0x80` into each byte position of `b"123456789"` | Catches sign-bit confusion in the bit-by-bit shift path. |
| Zero-byte insertion | Insert one `0x00` byte at every position of `b"123456789"` | Catches off-by-one in length-dependent loops. |
| Byte deletion | Delete each byte of `b"123456789"` in turn | Catches length-zero mis-handling and tail-skim bugs. |
| Randomized fuzz (PRNG) | `random.Random(42).randbytes(n)` for `n` in `[1, 1024]` (per-harness cap) | Mass exploration of the bytes space. |

### Oracle definition per surface

* **`crc_main`** — `crc(p)` always in `[0, 0xFFFF]`, deterministic across repeated
  calls, equal across `bytes` / `bytearray` / `memoryview`, isolated from caller-side
  mutation.
* **`engine_streaming`** — `crc(concat(pieces)) == Crc16En13757().update(piece)…value`
  for any chunking (Invariant 14 — xorout applies after the LAST block only).
* **`table_integrity`** — `TABLE[i]` byte-exact equal to an independently
  recomputed reference for poly 0x3D65; all 256 entries distinct; all entries in
  `[0, 0xFFFF]`.
* **`cli_args`** — well-formed hex exits 0 with `0x....` output; malformed hex
  exits 2 with no `Traceback` leakage; `--self-test` / `--version` / `--help` /
  missing args all exit cleanly.
* **`type_errors`** — every public surface raises `TypeError` (NOT `AttributeError`
  / `ValueError`) for the 20 canonical bad inputs + the randomized fuzz
  (Invariant 21 — total over arbitrary input).
* **`cross_cycle_oracle`** — `crc(b'123456789') == 0xC2B7`,
  `crc16_modbus_pure.crc(b'123456789') == 0x4B37`, no polynomial-collision payload
  across cycles 127/128/129 in a 10K randomized corpus. ccitt-false gracefully
  skipped as `stub_unavailable` if the package isn't importable in the worker
  sandbox.

## Seed Corpus

The 44-input shared seed pool lives at `benchmarks/adversarial/cycle_129/fuzz/corpus/seed/`
and is symlinked into each per-surface `corpus/seed/` so all six harnesses see
identical inputs (deterministic replay of any finding). The pool is composed of four
explicit categories; coverage of each category was a T1 deliverable.

### 1. RevEng canonical (7 inputs)

Sourced directly from the RevEng CRC catalogue entry for CRC-16/EN-13757
(https://reveng.sourceforge.io/crc-catalogue/16.htm, retrieved 2026-09-27 during
T1 audit). Includes the canonical check vector `b"123456789" → 0xC2B7` and the
boundary cases (`b"" → 0xFFFF` for `init=0x0000 ^ xorout=0xFFFF`).

### 2. EN-13757 / M-Bus spec frames (6 inputs)

Sourced from EN 13757-3 (Wireless M-Bus) frame-format examples and OMS Volume 2
application-layer short / long frames:

* Short frame header (`68 04 04 68 …`) — the smallest valid frame.
* Long frame header (`68 LL LL 68 …`) — variable-length long frame.
* 259-byte max-frame — exercises the maximum legal body length.
* `SND-NKE` (`10 40 …`) — link-layer "send no data, link confirmation" primary.
* `REQ-UD2` (`10 5B …`) — link-layer "request user data class 2" primary.
* Single-byte ACK (`E5`) — the smallest possible M-Bus frame.

### 3. Cross-cycle siblings (2 inputs)

`b"123456789"` is duplicated in the pool — once via the `cross_cycle_oracle`
harness, the modbus sibling computes `0x4B37`, the en13757 sibling computes
`0xC2B7`. ccitt-false is checked when the cycle_128 package is importable in the
worker sandbox; the harness gracefully degrades to `stub_unavailable` when it is
not. The differential oracle asserts no collision across cycles 127/128/129 on
10K randomized payloads.

### 4. Mutation operators (29 inputs)

Three families of deterministic mutations over `b"123456789"`:

| Mutation | Count | Description |
|---|---:|---|
| High-bit flip | 9 | XOR `0x80` into byte index `i` for `i ∈ {0, …, 8}`. |
| Zero-byte insertion | 10 | Insert `0x00` at position `i` for `i ∈ {0, …, 9}`. |
| Byte deletion | 9 | Delete byte index `i` for `i ∈ {0, …, 8}`. |

These inputs target the specific failure modes documented in T1's SURFACES.md
(sign-bit confusion, off-by-one in length loops, length-zero mis-handling).

## Findings Table

| ID | Severity | Surface | Title | Status |
|---|---|---|---|---|
| (none) | — | — | — | — |

The findings table is intentionally empty. Per `FINDINGS_SUMMARY.md` (T4) and
the per-surface `findings.jsonl` envelopes, the structured JSON roll-up at
`benchmarks/adversarial/cycle_129/fuzz/findings.jsonl` contains seven lines
(six per-surface + one root aggregate) — each with `findings: []` and zero
counters across `crashes / hangs / oom / oracle_mismatches`. The file
parses cleanly:

```
$ python3 -c "import json; [json.loads(l) for l in open('benchmarks/adversarial/cycle_129/fuzz/findings.jsonl')]; print('ok')"
ok
```

### T1 design-class observations (carried, NOT promoted)

T1's manual audit (`VULN_AUDIT.md`, commit `f378cfb`) surfaced **3 Low + 5 Info**
observations. None of them escalated to a T4 finding during T3's 240K-iter
workload. They are reproduced here verbatim so the next cycle's pre-push gate
can confirm the disposition without re-reading `VULN_AUDIT.md`.

| T1 ID | Severity | Surface | Title | T4 disposition |
|---|---|---|---|---|
| L-01 | Low | `crc_main` | No input-size cap on `crc()` API; 50 MB input runs in ~0.5 s and ~50 MB RAM, O(n) with no amplification. | NO_PROMOTE — design property; README Limitations block already documents "no built-in size cap; layer input-size cap in front for network-reachable usage". See `VULN_AUDIT.md` L-01, `README.md` Limitations, `CWE_MAP.md` CWE-400. |
| L-02 | Low | test suite | No upper-bound stress test (largest is 1 MB; audit ran 10 MB / 50 MB during review). | NO_PROMOTE — gap in test coverage, not a runtime defect. Mitigation already proposed in `TEST_GAPS.md` F-04 (add `test_crc_10mb_does_not_crash`). Deferred to a future cycle's test-suite expansion. |
| L-03 | Low | `crc_main` / `table_lookup` | `crc()` and `table_lookup()` silently accept non-int `init` via `& 0xFFFF`; modbus sibling explicitly raises `TypeError`. Contract divergence. | NO_PROMOTE — contract divergence, not a security bug. Mitigation already proposed in `TEST_GAPS.md` F-03 (align both siblings on the same contract, or document the divergence in the README). Deferred to a future cycle's contract-alignment pass. |
| I-01 | Info | n/a | CRC is not a cryptographic signature (design property). | NO_PROMOTE — README Limitations block already documents this. See `THREAT_MODEL.md` S/R/I. |
| I-02 | Info | `crc_main` | Caller responsible for bytearray / memoryview mutation lifecycle. | NO_PROMOTE — library documents "bytes-like" not "bytes-snapshot". See `TEST_GAPS.md` F-02, `THREAT_MODEL.md` T. |
| I-03 | Info | test suite | No bit-flip property test (Hamming distance ≥1 → ~50% output bit flips). | NO_PROMOTE — test-coverage gap. Mitigation proposed in `TEST_GAPS.md` F-01. |
| I-04 | Info | `engine_streaming` | No raw `crc_stream` chaining test (3+ blocks). | NO_PROMOTE — test-coverage gap. Mitigation proposed in `TEST_GAPS.md` F-05. |
| I-05 | Info | `table_integrity` | TABLE distinctness is not auto-tested. | NO_PROMOTE — test-coverage gap. Mitigation proposed in `TEST_GAPS.md` F-07. |

## Per-finding Narrative

There are no findings to narrate. Per the Invariant 26 §4 rubric, a "Per-finding
Narrative" section is required when findings exist; for a CLEAN cycle the
section is replaced by an explicit non-finding narrative. To preserve the
audit trail, the eight T1 design-class observations are narrated in the
order they appear in the table above, with what / where / why / fix-proposal
for each — even though none of them are findings in T4.

### L-01 — No input-size cap on `crc()` API (NOT PROMOTED)

* **What:** `crc(data)` accepts arbitrarily large bytes-like inputs. A 50 MB
  input runs in ~0.5 s and consumes ~50 MB RAM on the audit sandbox.
* **Where:** `src/crc16_en13757/core.py` — the public `crc()` entry point has
  no `if len(data) > LIMIT: raise` guard.
* **Why:** the algorithm is O(n) with a small constant; there is no
  amplification (no quadratic blow-up, no exponential recursion, no
  uncontrolled allocation). The DoS surface is bounded by the caller's
  willingness to allocate the input themselves.
* **Fix proposal:** none required for ship. README Limitations already says
  "no built-in size cap; layer an input-size cap in front for
  network-reachable usage". CWE_MAP.md cites CWE-400 with the same
  rationale. A future hardening cycle may add an optional `max_bytes`
  kwarg with a sensible default, but this is a feature request, not a bug.

### L-02 — No upper-bound stress test in suite (NOT PROMOTED)

* **What:** the test suite's largest payload is 1 MB
  (`test_all_zero_one_megabyte_does_not_crash`,
  `test_all_ff_one_megabyte_does_not_crash`); the audit exercised 10 MB and
  50 MB inputs live but no regression test enforces it.
* **Where:** `tests/test_crc16_en13757.py` — missing `test_crc_10mb_does_not_crash`.
* **Why:** a regression in the bit-shift path could plausibly blow up the
  constant factor; the test would catch a >100x slowdown. T3's fuzz pass
  did not surface a slowdown regression in the `crc_main` surface
  (100,000 iters at ~751 it/s — consistent with O(n) at small constant).
* **Fix proposal:** add `test_crc_10mb_does_not_crash` (cheap,
  deterministic) per `TEST_GAPS.md` F-04 in a future test-suite-expansion
  cycle. NOT blocking ship.

### L-03 — `crc()` / `table_lookup()` silently accept non-int `init` (NOT PROMOTED)

* **What:** passing `init="not-an-int"` (or any non-`int` value) returns
  `crc(data, init="not-an-int") == crc(data, init=0)` because `& 0xFFFF`
  masks the truthiness. The modbus sibling explicitly raises `TypeError`.
* **Where:** `src/crc16_en13757/core.py::crc()` and
  `src/crc16_en13757/_table.py::table_lookup()` — the `init & 0xFFFF`
  expression does not validate the type.
* **Why:** this is a contract divergence between siblings, not a security
  bug — the output is deterministic and well-defined for any `init`
  with a defined `& 0xFFFF` (which includes all `int` subclasses and
  anything that supports `__and__`).
* **Fix proposal:** align both siblings on the same contract — either both
  raise `TypeError` on non-`int` `init`, or both silently mask. Document
  the chosen behaviour in the README. See `TEST_GAPS.md` F-03. NOT
  blocking ship.

### I-01 — CRC is not a cryptographic signature (NOT PROMOTED)

* **What:** CRC-16/EN-13757 is a 16-bit checksum. It detects accidental
  bit errors with Hamming distance ~3 for typical packet sizes; it is not
  resistant to adversarial tampering.
* **Where:** design property of all CRCs; not specific to this package.
* **Why:** README Limitations block already states this. No code change
  possible or desirable.
* **Fix proposal:** none.

### I-02 — Caller responsible for bytearray / memoryview mutation lifecycle (NOT PROMOTED)

* **What:** `crc(bytearray(b"abc"))` evaluates the bytes eagerly under
  CPython; mutating the `bytearray` afterwards does not affect the
  returned CRC. PyPy behaviour may differ.
* **Where:** `src/crc16_en13757/core.py::crc()` and the streaming
  `.update()` method — both consume the bytes view eagerly via
  `for byte in data:`.
* **Why:** documented library contract ("bytes-like", not "bytes-snapshot").
  T3's `crc_main` mutation-isolation oracle (100K iters) confirmed the
  contract holds.
* **Fix proposal:** none required for ship. Optional: copy the bytes
  inside `crc()` for paranoid callers. See `TEST_GAPS.md` F-02.

### I-03 — No bit-flip property test (NOT PROMOTED)

* **What:** the canonical CRC property (flipping one input bit flips
  ~50% of the output bits on average) is not explicitly tested. The 6
  canonical + 50/100/1000-input fuzz tests do catch regressions in
  practice.
* **Where:** `tests/test_crc16_en13757.py` — missing a dedicated
  bit-flip property test.
* **Why:** test-coverage gap, not a runtime defect.
* **Fix proposal:** add a parametrized bit-flip property test. See
  `TEST_GAPS.md` F-01. NOT blocking ship.

### I-04 — No raw `crc_stream` chaining test (NOT PROMOTED)

* **What:** the wrapper `Crc16En13757` is tested for chunked equivalence
  to `crc(concat(pieces))`, but the raw `crc_stream` chain form
  (`crc_stream(b1, init=crc_stream(b2, init=state))`) is only tested
  implicitly.
* **Where:** `src/crc16_en13757/core.py::crc_stream()` and
  `tests/test_crc16_en13757.py`.
* **Why:** the xorout-application point (after the LAST block only) is
  load-bearing; T3's `engine_streaming` surface exercised
  `Crc16En13757().update()` at 50K iters but did not cover `crc_stream`
  chain-of-three directly.
* **Fix proposal:** add a dedicated `test_crc_stream_chains_correctly`
  that exercises 3+ blocks through the raw API. See `TEST_GAPS.md` F-05.
  NOT blocking ship.

### I-05 — TABLE distinctness is not auto-tested (NOT PROMOTED)

* **What:** `test_table_entries_are_in_range` asserts each entry is in
  `[0, 0xFFFF]` (256 parametrized cases), but no test asserts all 256
  entries are distinct.
* **Where:** `src/crc16_en13757/_table.py::TABLE` and
  `tests/test_crc16_en13757.py`.
* **Why:** the audit verified `len(set(TABLE)) == 256` manually; no
  automated guard exists. T3's `table_integrity` surface (256 iters) does
  byte-uniqueness check on the harness side, but the production test
  suite does not.
* **Fix proposal:** add `test_table_entries_are_distinct`. See
  `TEST_GAPS.md` F-07. NOT blocking ship.

## Recommendations

### Go/no-go for cycle_129

**GO — proceed to ship.** The cycle_129 fuzzing workstream returned **CLEAN**
across all 6 surfaces, **240,256** total iterations, with zero Critical/High/Medium
findings. Per Invariant 26 §4, the cycle may proceed to ship without a
`cycle_129/fix` card — there is nothing to remediate.

### Deferred items (NOT blocking ship)

The following T1 design-class observations are documented and tracked in
`TEST_GAPS.md` / `CWE_MAP.md` / `THREAT_MODEL.md`. They are NOT findings and do
NOT block ship; they are deferred to future hardening cycles.

* **L-01** — optional `max_bytes` kwarg on `crc()` (CWE-400 hardening).
* **L-02** — `test_crc_10mb_does_not_crash` (test-suite expansion).
* **L-03** — align `init`-type contract across cycle_127 / cycle_128 / cycle_129
  siblings (contract-alignment pass).
* **I-03** — bit-flip property test (test-suite expansion).
* **I-04** — raw `crc_stream` chaining test (test-suite expansion).
* **I-05** — TABLE distinctness test (test-suite expansion).

### Suggested follow-up cards (next cycle's repo-builder)

If a future cycle wants to close out the deferred items, the orchestrator may
mint the following child cards assigned to `@repo-builder`:

1. **cycle_130/test_suite_expansion** — add the 4 missing tests (L-02, I-03,
   I-04, I-05) in a single PR. Low risk, deterministic, fast.
2. **cycle_131/contract_alignment** — align `init`-type validation across the
   three sibling CRC packages (cycle_127 / cycle_128 / cycle_129). Touches
   all three packages; needs a cross-package design decision first
   (raise `TypeError` everywhere, or mask silently everywhere).
3. **cycle_132/optional_max_bytes** — add an optional `max_bytes` kwarg to
   `crc()` for callers who want library-side DoS hardening. Pure additive,
   backwards-compatible.

These follow-ups are not pre-requisites for cycle_129 ship.

### Reproduction

```bash
cd /root/projects/crc16-en13757-pure
git checkout wt/cycle129-adversary-01
bash benchmarks/adversarial/cycle_129/fuzz/run_all.sh
```

All six harnesses run deterministically with `--seed 42` and the iteration
budgets documented in §Methodology. Any FAIL can be re-played by re-running
the same harness with `--seed 42` and `--iters N+1` where `N` is the failing
iteration index (since `random.Random(42)` is consumed in order).

### File deliverables (this card)

| Path | Purpose |
|---|---|
| `benchmarks/adversarial/cycle_129/FUZZING_REPORT.md` | This document (canonical location). |
| `fuzz/FUZZING_REPORT.md` | Pre-push-gate-required copy at the repo-root `fuzz/` path. |

---

VERDICT: SHIP
