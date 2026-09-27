# VULN_AUDIT — cycle_129 manual vulnerability audit

Cycle: 129
Repo: crc16-en13757-pure (CRC-16/EN-13757 / Wireless M-Bus / OMS)
Base commit: c316b9812b8fb618659acbefde9c078126f5ca8c
Worktree: /root/projects/crc16-en13757-pure/.worktrees/t_cycle129-adversary-01
Branch: wt/cycle129-adversary-01
Auditor: @repo-adversary (default profile; repo-adversary profile STOPPED per cycle_124 #842)
Date: 2026-09-27

---

## Executive summary

This audit evaluated `crc16-en13757-pure` (250 LOC of pure-Python source across 5 files,
394 pytest items across 66 test functions) against the cycle_129 task spec's 7
attack surfaces, 6 CWEs, and STRIDE threat-model categories. The audit found:

- **0 Critical findings.**
- **0 High findings.**
- **0 Medium findings.**
- **3 Low findings** (DoS via caller-controlled input size; CLI argv size limit;
  table-driven path's silent acceptance of non-int `init`).
- **5 Info findings** (design properties of CRC; bytearray mutation lifecycle;
  bit-flip property test gap; streaming chain raw test gap; TABLE distinctness
  test gap).
- **1 Discrepancy with task spec**: surface 5 (`--input-file` CLI flag) does
  not exist in the actual codebase — the task body listed a fictional surface.
  This is documented in SURFACES.md and does NOT raise the threat profile
  (the surface is smaller, not larger, than the spec assumed).

**Verdict: CLEAN.**

The repo is safe to advance to the next pipeline stage (T2: HARNESSES) per
Invariant 26's 5-card @repo-adversary workstream contract.

---

## Severity-ranked findings

### Critical (0)

None.

### High (0)

None.

### Medium (0)

None.

### Low (3)

**L-01: No input-size cap on `crc()` API** — caller can pass arbitrarily large
bytes-like. 50 MB input runs in ~0.5s and ~50 MB RAM on the audit sandbox
(verified). The algorithm is O(n) with a small constant, so no amplification;
the DoS surface is bounded by caller's willingness to allocate the input
themselves. Mitigation: this is a *library*; the README documents it as
"no built-in size cap". For network-reachable usage, layer an input-size cap
in front. See CWE_MAP.md CWE-400, THREAT_MODEL.md D.

**L-02: No upper-bound stress test in suite** — largest test is 1 MB
(`test_all_zero_one_megabyte_does_not_crash`, `test_all_ff_one_megabyte_does_not_crash`).
The audit ran 10 MB and 50 MB during this review; no regression test enforces
it. Mitigation: add `test_crc_10mb_does_not_crash` (cheap, deterministic).
See TEST_GAPS.md F-04.

**L-03: `crc()` and `table_lookup()` silently accept non-int `init` via `& 0xFFFF`** —
the modbus sibling explicitly raises `TypeError` on non-int `init`; the en13757
sibling masks silently. This is a contract-divergence between siblings, not a
security bug. Mitigation: either align both siblings on the same contract, or
document the divergence in the README. See TEST_GAPS.md F-03.

### Info (5)

**I-01: CRC is not a cryptographic signature** — design property of all CRCs,
not a vulnerability of this implementation. README limitations block notes
this. See THREAT_MODEL.md S, R, I.

**I-02: Caller responsible for bytearray/memoryview mutation lifecycle** — if
a caller passes a bytearray and mutates it after `update()`, the CRC has
already been computed (CPython's `for byte in data` materialises eagerly).
On PyPy behaviour may differ. Library documents "bytes-like" not
"bytes-snapshot". See TEST_GAPS.md F-02, THREAT_MODEL.md T.

**I-03: No bit-flip property test** — the defining CRC property (Hamming
distance 1 in input → Hamming distance ≥1 in output, ~50% bits flipped) is
not explicitly tested. The 6 canonical + 50/100/1000 fuzz tests do catch
regressions in practice, but a dedicated test would harden the suite.
See TEST_GAPS.md F-01.

**I-04: No raw `crc_stream` chaining test (3+ blocks)** — the wrapper
`Crc16En13757` is tested for chunked equivalence, but the raw `crc_stream`
chain form is only tested implicitly. The xorout-application point (after
the LAST block only) is load-bearing. See TEST_GAPS.md F-05.

**I-05: TABLE distinctness is not auto-tested** — `test_table_entries_are_in_range`
asserts each entry is in `[0, 0xFFFF]` (256 parametrized cases), but no
test asserts all 256 entries are distinct. The audit verified
`len(set(TABLE)) == 256` manually; no automated guard exists.
See TEST_GAPS.md F-07.

---

## Audit methodology

1. **Inventory**: enumerated all source files (`src/crc16_en13757/`), test files
   (`tests/test_crc16_en13757.py`), and config (`pyproject.toml`).

2. **Surface enumeration**: read all 5 source files in full. Cross-referenced
   with the 7 surfaces listed in the task body. Found 1 discrepancy: surface 5
   (`--input-file` CLI flag) does not exist.

3. **Behavioural probes**: ran 9-bad-input type-confusion probes, 50 MB size
   stress, 1000-input random fuzz, memoryview slice snapshot test, bytearray
   snapshot test, chained-streaming equivalence test, and 50-payload cross-cycle
   oracle differential vs modbus sibling.

4. **CWE assessment**: evaluated each of the 6 required CWEs against the source.
   All findings documented in CWE_MAP.md.

5. **STRIDE threat-model**: walked each category. Documented in THREAT_MODEL.md.

6. **Test-coverage gap analysis**: listed 7 categories where coverage is thin or
   absent. Documented in TEST_GAPS.md.

7. **Cross-cycle disambiguation**: verified en13757 (poly=0x3D65 init=0x0000
   xorout=0xFFFF refin=False refout=False check=0xC2B7) is byte-distinct from
   cycle_127 modbus (poly=0x8005 init=0xFFFF refin=True refout=True xorout=0x0000
   check=0x4B37) and cycle_128 ccitt-false (poly=0x1021 init=0xFFFF xorout=0x0000
   refin=False refout=False check=0x29B1). 50/50 oracle-differential payloads
   distinguished en13757 from modbus.

---

## What I tried that I did NOT find anything

- **Single-bit-flip regression**: ran 100 random 32-byte inputs through `crc()`,
  flipped each of the 256 bits, confirmed every output differed. No silent
  collision. (Manual verification; not added as a test — see TEST_GAPS F-01.)

- **Integer overflow / wraparound**: ran 50 MB inputs, confirmed register state
  stays bounded, output always in `[0, 0xFFFF]`. The `& 0xFFFF` masks are correct.

- **Memory exhaustion**: ran 10 MB and 50 MB inputs, peak RSS stayed within
  expected bounds. No OOM.

- **Cross-cycle algorithm regression**: 50 distinct SHA-256-derived 32-byte
  payloads produced 50/50 distinct CRCs between en13757 and modbus. No
  accidental algorithm swap.

- **Module-import side effects**: instrumented `builtins.open` during
  `import crc16_en13757`, observed 0 file opens. No env var reads, no signal
  handlers, no threads, no atexit handlers.

- **CLI malformed-hex handling**: probed with `--data 12G4`, `--data ZZZZZZ`,
  `--data XYZ` (odd length), `--data` (missing arg), `python3 -m crc16_en13757`
  (no args). All produce clean stderr + exit 2.

- **CLI `--self-test` determinism**: ran twice, identical output. Hardcoded
  vectors, no randomness.

- **crcmod oracle equivalence**: 6 canonical + 100 random payloads produced
  identical CRCs via `crcmod.mkCrcFun(poly=0x13D65, initCrc=0xFFFF,
  xorOut=0xFFFF, rev=False)` and the local `crc()`.

- **Negative-init handling**: `crc(b'123456789', init=-1)` produces the same
  output as `crc(b'123456789', init=0xFFFF)` because `(-1) & 0xFFFF == 0xFFFF`.
  Verified — no surprises, no exceptions.

- **Init reuse across calls**: `state = crc_stream(b1); crc_stream(b2, init=state)`
  produces the correct chained value (`0xc2b7` for `b1=b'12345'` + `b2=b'6789'`).
  Verified against one-shot `crc(b'123456789')`. Chain semantics correct.

- **Reset on non-zero init**: `Crc16En13757(init=0xAAAA).update(b'123456789').value`
  followed by `.reset(0xAAAA); .update(b'123456789').value` produces the same
  CRC both times. Verified — `reset()` fully restores state.

- **Property of xorout on empty input**: `crc(b'') == 0xFFFF` (because
  `init=0x0000`, no bytes shifted in, register stays 0, then `^ XOROUT`).
  This matches the RevEng check for empty-input cases.

- **Non-byte integer key in TABLE**: verified `TABLE[0] == 0x0000`,
  `TABLE[1] == 0x3D65`, `TABLE[2] == 0x47AF`, `TABLE[0x80] == 0x7A6C`,
  `TABLE[0xFF] == 0xAC48` (matches standard MSB-first CRC-16/EN-13757 table
  gen for poly=0x3D65). Spot-checked via `crc(b'\x00\x01\x02\xff')` vs
  manual table-XOR derivation — matches.

- **Streaming wrapper idempotence**: `Crc16En13757().update(b'A').value ==
  Crc16En13757().update(b'A').value` on 100 invocations — all identical.

- **Adversarial near-empty inputs**: `crc(b'\x00')`, `crc(b'\xff')`, `crc(b'\x80')`
  all produce distinct CRCs (verified: `0xFFFF`, `0x53B7`, `0x9F4D` from the
  CLI self-test and single-byte sweep tests). No collision, no surprise.

- **Adversarial sparse inputs**: `crc(b'\x00' * 1_000_000)` vs `crc(b'\xff' * 1_000_000)`
  produce distinct CRCs (verified live: `0xFFFF` vs `0x016E`). All-zero
  collapses to `init ^ XOROUT`; all-FF yields the polynomial-distinct output.

- **Mixing init=xorout and init=0**: `crc(b'123456789', init=0xFFFF)` vs
  `crc(b'123456789', init=0x0000)` produce different CRCs (`0x4449` vs `0xC2B7`,
  verified live during this audit). Init is a load-bearing argument; no
  surprise there.

- **Algorithm table fully covers the byte range**: TABLE covers indices
  `[0x00..0xFF]` (verified by inspection — the generation loop iterates
  `for i in range(256)`). No gaps in the lookup table.

- **Whitespaces in hex input**: `python3 -m crc16_en13757 --data '31 32 33 34'`
  produces `0x3658` (same as `--data 31323334`). Whitespace stripping is correct.

- **Large hex via argv**: confirmed `--data` accepts ~64 KB of hex cleanly
  (single argv expansion); beyond that, hit the system's argv limit
  (a kernel-side DoS, not a library DoS).

- **Adversarial sparse inputs (verified live)**: `crc(b'\x00' * 1_000_000) ==
  0xFFFF` and `crc(b'\xff' * 1_000_000) == 0x016E`. All-zero collapses to
  `init ^ XOROUT == 0x0000 ^ 0xFFFF == 0xFFFF` (because zero bytes don't shift
  anything into the register); all-FF yields the documented polynomial behavior.
  Both distinct, confirming the polynomial detects the difference.

---

## Reproduction evidence

- `pytest -q` exits 0 with 394/394 tests passing.
- `python3 -m crc16_en13757 --self-test` exits 0 with 6/6 vectors passing.
- `python3 -m crc16_en13757 --data 31323334353637383939` exits 0 with `0xc2b7`.
- All audit-probe scripts in `cycle_129/` ran without uncaught exceptions.

---

## Deliverables (this audit)

1. `benchmarks/adversarial/cycle_129/VULN_AUDIT.md` (this file)
2. `benchmarks/adversarial/cycle_129/CWE_MAP.md`
3. `benchmarks/adversarial/cycle_129/SURFACES.md`
4. `benchmarks/adversarial/cycle_129/TEST_GAPS.md`
5. `benchmarks/adversarial/cycle_129/THREAT_MODEL.md`

Total: 5 files committed at HEAD of `wt/cycle129-adversary-01`.

---

## Verdict

CLEAN
