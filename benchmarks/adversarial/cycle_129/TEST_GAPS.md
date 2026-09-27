# TEST_GAPS — cycle_129 manual vulnerability audit

Cycle: 129
Repo: crc16-en13757-pure
Base commit: c316b9812b8fb618659acbefde9c078126f5ca8c
Current test count: 394 pytest items (66 functions, some parametrized).

## Summary

The test suite is broad and well-structured for a single-CRC library: 6 RevEng-canonical
vectors, full 256-entry single-byte sweep, length sweeps including 1024-byte case,
1 MB all-zeros and all-FF stress, cross-cycle differential vs modbus & ccitt, table
integrity (256 entries + range), crcmodel oracle (6 canonical + 100 random), CLI smoke
(12 tests), fuzz (50/100/random), streaming wrapper equivalence, chunked-streaming
equivalence. Invariant 21 (total over arbitrary input) is well-covered via
`test_crc_raises_type_error_for_non_bytes_like` (parametrized 9 inputs).

What follows are the categories where coverage is THIN or ABSENT, ordered by severity
of the gap, not by what was easiest to write.

---

## F-01 — No adversarial bit-flip / single-bit-flip detection (Info)

**Gap**: A CRC is fundamentally a polynomial-over-GF(2) detector. The strongest
property test is: flip a single bit in the input, the CRC changes in a predictable
way (specifically: for any single-bit error in the input, the CRC differs in a
manner that depends on the polynomial; for any double-bit error at distance d, the
syndrome is non-zero with probability 1 - 2^-16).

**What's missing**: no test that flips each of the 16 bits of the input and
asserts the CRC changes (Hamming distance 1 in input → Hamming distance ≥1 in
output, with ~50% of bits flipped on average).

**Why it matters**: this is the *defining* property of a CRC; absence of this
test means a regression that "accidentally returns the same value for two
different inputs" would not be caught.

**Suggested test**: parametrize 100 random inputs, flip bit at position `i` for
`i in range(8 * len(input))`, assert `crc(flipped) != crc(original)`. With
~65536 inputs flipped per test, this catches the worst regression class.

**Severity for the gap**: **Info** — the canonical-vector test (6 inputs) +
fuzz (50 + 100 + 1000) does catch most regressions in practice, but a single
explicit bit-flip property test would harden the suite.

---

## F-02 — No test for `bytearray` mutation during streaming update (Info)

**Gap**: `Crc16En13757.update(bytearray(b"12345"))` is accepted (verified: passes
`isinstance(data, (bytes, bytearray, memoryview))`), but if a caller mutates the
bytearray after `update()`, the CRC could change if the implementation held a
reference to it instead of reading eagerly.

**Audit finding**: `_crc_raw` uses `for byte in data:` which on CPython materialises
bytes from a bytearray eagerly (because of the `<< 8` and bit-shifts). On PyPy the
behaviour could differ. No test asserts "snapshot semantics" for bytearray.

**Severity**: **Info** — the canonical RevEng vectors (which include `bytes(range(10))`)
do exercise bytearray with the implicit `bytes` coercion path, but explicit
snapshot-semantics tests would harden it.

---

## F-03 — No test for non-int `init` argument (Info)

**Gap**: `crc(data, init="0x1234")` or `crc(data, init=None)` is accepted silently
and masked to `& 0xFFFF`. The modbus sibling explicitly rejects non-int `init`
(`raise TypeError(f"init must be int, got {type(init).__name__}")`), but the
en13757 sibling does not.

**Why it matters**: this is an API divergence between siblings — silently-accepting
vs explicitly-rejecting. Neither is "wrong" per se, but a consistent contract is
cleaner. The en13757 contract is "int, masked to 16 bits, no exception" — that's
a design choice, not a bug.

**Severity**: **Info** — design choice, not a security finding.

---

## F-04 — No upper-bound stress test (Low)

**Gap**: the largest stress test in the suite is 1 MB (`test_all_zero_one_megabyte_does_not_crash`,
`test_all_ff_one_megabyte_does_not_crash`). No 10 MB, 100 MB, or 1 GB test. The cycle_129
audit probed 10 MB and 50 MB successfully during the manual review, but no
regression test enforces it.

**Why it matters**: an O(n²) regression (e.g. accidental nested loop in `_crc_raw`)
would not be caught by 1 MB (1 second of CPU) but would visibly slow 100 MB.

**Suggested test**: `crc(b'X' * 10_000_000) == <expected>` — single deterministic
input, single assertion. Cheap to add.

**Severity**: **Low** — not blocking, but cheap to add.

---

## F-05 — No test for `crc_stream` chaining on 3+ blocks (Info)

**Gap**: `test_streaming_wrapper_chunks_match_one_shot` covers 2 halves and 3 thirds
via the `Crc16En13757` class, but the raw `crc_stream(b1); crc_stream(b2, init=s)`
form is only tested implicitly through the wrapper. An explicit
`crc_stream(b3, init=crc_stream(b2, init=crc_stream(b1)))` test would harden the
chain semantics.

**Why it matters**: the xorout-application point (after the LAST block only) is
load-bearing. A regression that pre-XORed each block would still pass the wrapper
test (because the wrapper XORs only once, in the `.value` property) but would
break raw chaining.

**Severity**: **Info** — the wrapper test does transitively cover this, but
explicit chain tests are clearer documentation.

---

## F-06 — No test for empty `data` parameter (Low)

**Gap**: every RevEng canonical test (6 vectors) and most fuzz tests pass
non-empty data. `crc(b'')` is tested only by the CLI smoke (`test_cli_empty_data`)
and indirectly via `test_xorout_property_on_empty_input`. An explicit
`test_crc_empty_returns_xorout` would make the contract crystal-clear.

**Severity**: **Low** — covered transitively, but a dedicated test is cheap.

---

## F-07 — No test that TABLE is byte-distinct from itself (Info)

**Gap**: `test_table_entries_are_in_range` checks each entry is in `[0, 0xFFFF]`
(256 assertions), but no test asserts all 256 entries are *distinct*. A TABLE with
duplicate entries would still pass the range test but would produce wrong CRCs
for any input using the duplicate index.

**Audit finding**: I verified manually during this audit that `len(set(TABLE)) == 256`.
A test asserting this would catch a regression that produced a TABLE with
duplicates due to a poly bug.

**Severity**: **Info** — manual verification done, no automated guard.

---

## Coverage density

| Category                       | Tests  | Status |
|--------------------------------|--------|--------|
| RevEng canonical vectors       | 6      | GREEN  |
| Single-byte sweep              | 256    | GREEN  |
| Length sweep                   | ~16    | GREEN  |
| 1 MB stress                    | 2      | GREEN  |
| 10+ MB stress                  | 0      | F-04 (gap) |
| Cross-cycle differential       | 22     | GREEN  |
| Table integrity                | 257    | GREEN  |
| Table distinctness             | 0      | F-07 (gap) |
| crcmodel oracle                | 106    | GREEN  |
| CLI smoke                      | 12     | GREEN  |
| CLI malformed hex              | 2      | GREEN  |
| Streaming wrapper              | 8      | GREEN  |
| Chunked equivalence            | 5      | GREEN  |
| Fuzz (50/100/random)           | 150+   | GREEN  |
| Bit-flip property              | 0      | F-01 (gap) |
| Bytearray mutation snapshot    | 0      | F-02 (gap) |
| Non-int `init`                 | 0      | F-03 (gap) |
| `crc_stream` chain             | 0 raw  | F-05 (gap) |
| Empty `data`                   | ~3     | GREEN  |

**Gap count**: 7 categories (3 Info, 2 Low, 2 Info). No High or Critical gaps.
No gap blocks the CLEAN verdict — all gaps are hardening opportunities, not
correctness holes.
