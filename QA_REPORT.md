# QA Report — crc16-en13757-pure (cycle_129)

| Field | Value |
|---|---|
| Cycle | 129 |
| Repository | `crc16-en13757-pure` |
| HEAD (final) | `7973a2585d54571f000b1259a5d9527a19d3cdfe` |
| Branch | `wt/cycle129-build` |
| Spec | `SPEC.md` (12 LOCKED ACs, 9 sections, 3 HTTP-200 primary sources) |
| Algorithm | CRC-16/EN-13757 — poly=0x3D65, init=0x0000, xorout=0xFFFF, **NO bit reflection**, check=0xC2B7 |
| Final verdict | **SHIP** |

---

## qa1 (initial QA) — outcome: FIX → README stub

Performed by `t_e315af28`. **7 of 8 checks PASSED**. The single Honest-pillar
FAIL was that the README delivered by build commit `1a90b9e` was a 163-byte
scaffold stub — the commit message falsely claimed "Invariant 16, 6 sections"
but only updated `CHANGELOG.md` (verified by `git show --stat`). Cycle_126 #870
fabrication pattern — fix card `t_10375480` raised to a real README.

---

## qa2 (re-QA after fix) — outcome: SHIP

Performed by `t_1aad424f` against HEAD `7973a25` (post-fix). All 8 mandatory
checks PASSED.

### 1. README audit (Invariant 16) — PASS

`grep -n '^# \|^## ' README.md`:

```
 1:# crc16-en13757
16:## Quick Start
34:## ⚡ Performance & Benchmarks
78:## Why crc16-en13757?
118:## Key Features & API Reference
239:## Limitations & Non-Goals
266:## License
```

Canonical order verified: Title → Quick Start → Performance → Why → Key
Features & API → Limitations → License (6 `## ` sections + 1 `#` title).

- `wc -c README.md` = **11011 bytes** (≥ 2500 byte floor: PASS)
- Install line: `pip install git+https://github.com/prasad-a-abhishek/crc16-en13757.git` (git+ form, NOT PyPI)
- Limitations section explicitly excludes `CRC-16/MODBUS` (cycle_127 sibling,
  `0x4B37`, refin/refout `True`, xorout `0x0000`) and `CRC-16/CCITT-FALSE`
  (cycle_128 sibling, `0x29B1`, init `0xFFFF`, xorout `0x0000`) — cross-CRC
  disambiguation unambiguous.
- Bench table + `python3 benchmarks/run_benchmark.py` reproduction line present.

### 2. AC regression (12 ACs from SPEC.md §3) — PASS

Spot-checked against the unchanged algorithm:

| AC | Input | Expected | Got | Pass |
|---|---|---|---|---|
| AC1 | `crc(b"")` | `0xFFFF` | `0xffff` | ✓ |
| AC2 | `crc(b"123456789")` | `0xC2B7` | `0xc2b7` | ✓ |
| AC12 | `crc("not bytes")` | `TypeError` | `TypeError: expected bytes-like, got str` | ✓ |
| AC12 | `crc(None)` | `TypeError` | `TypeError: expected bytes-like, got NoneType` | ✓ |
| AC12 | `crc(12345)` | `TypeError` | `TypeError` | ✓ |
| AC12 | `crc([])` | `TypeError` | `TypeError` | ✓ |
| AC12 | `crc(object())` | `TypeError` | `TypeError` | ✓ |

All 12 ACs covered by the 394-test pytest suite (algorithm + tests untouched
by README fix; `src/` diff = 0 lines).

### 3. Full pytest — PASS

```
$ PYTHONPATH=src python3 -m pytest --tb=no -q
394 passed in 0.98s
```

394 collected, 394 passed, 0 failed, 0 skipped.

### 4. Fresh-venv smoke (post-fix) — PASS

```
$ python3 -m venv crc129_smoke2
$ pip install -e /root/projects/crc16-en13757-pure/.worktrees/t_cycle129-build
$ python3 -c "from crc16_en13757 import crc; print(hex(crc(b'123456789'))); print(hex(crc(b'')))"
0xc2b7
0xffff
```

`pip install -e` worked cleanly from outside the worktree; `from crc16_en13757
import crc` works; byte-exact RevEng check.

**crcmod oracle** (`pip install crcmod`):

```
crcmod.mkCrcFun(poly=0x13D65, initCrc=0xFFFF, xorOut=0xFFFF, rev=False)
  → crc(b"123456789") == 0xc2b7
```

This matches `crc(b"123456789") == 0xc2b7` byte-for-byte. (crcmod's `initCrc`
flag is applied at the high byte, hence `0xFFFF` here corresponds to the
canonical init=0x0000 + non-reflected byte ordering documented by EN 13757-3:2018
§6.2.) Independent manual reference implementation (poly=0x3D65, init=0x0000,
xorout=0xFFFF, MSB-first, no reflection) also produces identical output across
empty / `123456789` / `'A'` / `\x00\x01\x02\x03`.

Cleanup: `deactivate && rm -rf /tmp/crc129_smoke2`.

### 5. Fuzz inputs — PASS

```
crc(b'')                = 0xffff        (AC1 boundary)
crc(b'\xff' * 100000)   = 0xb850        (100 KB stress, 0.034s)
crc(bytearray(range(256))) = 0xb50d     (256 byte-class sweep)
crc(b'A' * 1000000)     = 0x95f5        (1 MB stress, 0.353s)
```

Stability: `crc(b"123456789") == crc(b"123456789")` deterministic.

No uncaught `ValueError` / `AttributeError` / `NameError` (Invariant 21). All
type-confusion inputs raise `TypeError` cleanly (AC12).

### 6. Secret scan — PASS

```
$ git grep -lE 'ghp_|pypi-AgEI|npm_[a-zA-Z0-9]+|sk-[a-zA-Z0-9]+|AKIA[0-9A-Z]{16}|BEGIN PRIVATE KEY' \
    -- '*.py' '*.md' '*.toml' '*.json' '*.cff' '*.yml'
(exit 1 — 0 hits)
```

No hardcoded tokens, API keys, credentials, or private secrets anywhere in
the repo.

### 7. Deps audit — PASS

```
$ grep -A2 '^dependencies' pyproject.toml
dependencies = []
```

Zero runtime dependencies. Optional `[test] = ["pytest>=7", "crcmod"]`
declared for the fuzzing / differential-test suite. Invariant zero-runtime-
deps satisfied.

### 8. Cross-cycle oracle disambiguation — PASS

```
cycle_127 crc16-modbus-pure:     crc(b"123456789") == 0x4B37
cycle_128 crc16-ccitt-pure:      crc(b"123456789") == 0x29B1
cycle_129 crc16-en13757-pure:    crc(b"123456789") == 0xC2B7   ✓
```

EN-13757 produces 0xC2B7 (MSB-first, init=0x0000, xorout=0xFFFF, no
reflection) — distinct from cycle_127's MODBUS (reflected, xorout=0x0000,
0x4B37) and cycle_128's CCITT-FALSE (MSB-first, init=0xFFFF, xorout=0x0000,
0x29B1). No confusion possible.

---

## Decision

All 8 mandatory checks PASS. Honest-pillar README gap from qa1 is closed
by fix card `t_10375480` (HEAD `7973a25`, README 11011 bytes, 6 sections in
canonical order, explicit cross-CRC-family exclusions in Limitations). The
algorithm, the 394/394 pytest suite, the RevEng byte-exact check, the
fresh-venv install, the deps=[], the secret scan, and the cross-cycle
oracle disambiguation are all clean.

Ready to ship to GitHub.

VERDICT: SHIP
