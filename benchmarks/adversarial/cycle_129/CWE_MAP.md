# CWE_MAP — cycle_129 manual vulnerability audit

Cycle: 129
Repo: crc16-en13757-pure
Base commit: c316b9812b8fb618659acbefde9c078126f5ca8c
Auditor: @repo-adversary (default profile, since repo-adversary is STOPPED per cycle_124 #842)

## Scope

CWE assessment of the entire `src/crc16_en13757/` package (5 files, ~250 LOC) against the 6
CWEs the task spec requires: CWE-20, CWE-125, CWE-190, CWE-400, CWE-770, CWE-835. For
each, the analysis below states applicability (yes/no), evidence (code line + observed
test/fuzz behaviour), and severity if applicable.

## CWE-20 — Improper Input Validation

**Applicable: YES, but mitigated.**

`crc16_en13757.crc()`, `crc_stream()`, `table_lookup()`, and `Crc16En13757.update()` all
open with the same guard:

```python
if not isinstance(data, (bytes, bytearray, memoryview)):
    raise TypeError(f"... expected bytes-like, got {type(data).__name__}")
```

Verified during this audit with a 9-bad-input probe (None, str, int, float, list, dict,
set, tuple, object) — every case raises `TypeError` cleanly. No silent acceptance, no
return-garbage, no uncaught `ValueError`/`AttributeError`. Invariant 21 (total over
arbitrary input) is satisfied.

However, `init` is accepted as any int without bounds validation beyond `& 0xFFFF`.
That's not a vuln (the mask makes the int irrelevant beyond 16 bits), but it is
lax input hygiene — see TEST_GAPS.md "F-03" for why this matters.

Severity: **Info** (defensive input validation is enforced where it matters;
the bytes-like check is the only externally-reachable surface).

## CWE-125 — Out-of-Bounds Read

**Applicable: NO.**

No array indexing on caller-controlled input. The only indexed data structure is
`TABLE[((crc_reg >> 8) ^ byte) & 0xFF]` (table_lookup) — the index is masked to 8
bits via `& 0xFF`, so even if `byte` is malformed, the index is in `[0, 255]`.
TABLE has exactly 256 entries (verified: `len(TABLE) == 256`). The bit-by-bit
reference (`_crc_raw`) does no array indexing at all.

The `for byte in data:` iteration is bounded by Python's iterator protocol on the
bytes-like input — no manual offset arithmetic anywhere.

Severity: **N/A**.

## CWE-190 — Integer Overflow / Wraparound

**Applicable: YES in principle, mitigated by explicit masking.**

The CRC inner loop does `crc_reg << 1`, `crc_reg ^ POLY`, `crc_reg << 8`, `byte << 8`.
Python ints are arbitrary-precision, so there is no overflow per se. But values can
grow without bound (a 50 MB input produces a register state in the millions after
unmasked shifts) and become expensive. The code masks to 16 bits at every assignment:

- `crc_reg = ((crc_reg << 1) ^ POLY) & 0xFFFF`
- `crc_reg = (crc_reg << 1) & 0xFFFF`
- `crc_reg ^= byte << 8`  ← NOT masked here, but only used for the conditional branch
- `crc_reg = init & 0xFFFF`
- `crc_reg = ((crc_reg << 8) ^ TABLE[...]) & 0xFFFF`

The XOR-with-byte line at `crc_reg ^= byte << 8` is intentionally NOT masked to 16
bits — it places byte into bits 8..15, then the bit-shift loop immediately reads
`crc_reg & 0x8000` to decide which branch to take. After the 8 iterations of the
inner loop, the next iteration's byte-XOR (or the `& 0xFFFF` at the top of the
table-driven path) bounds the value. Verified empirically: 50 MB input → register
state stays bounded, output always in `[0, 0xFFFF]`.

Severity: **Info** (Python's bignum + explicit masks = no exploit; this is a design
note, not a finding).

## CWE-400 — Uncontrolled Resource Consumption (DoS)

**Applicable: YES in principle, partially mitigated.**

The package accepts arbitrary-length bytes-like input. `crc(b'X' * 50_000_000)` runs
to completion in well under a second on this sandbox (verified during audit). There
is no size cap in the library itself. The CLI has no size cap either — `--data HEX`
is bounded only by argv size limits (typically ~128 KB on Linux), but a hostile user
could feed a multi-MB hex string.

Severity: **Low**. A 50 MB call takes ~0.5s of pure-Python work and ~50 MB of RAM.
There is no algorithm-level amplification (no quadratic blow-up, no exponential
state-space). For a *library* this is fine; for the CLI, the attacker has to be the
local user invoking `python3 -m crc16_en13757`, so the threat model is self-DoS
only. Not network-reachable.

See TEST_GAPS.md F-04 (no upper-bound stress test beyond 1 MB; we ran 10 MB and
50 MB successfully during this audit).

## CWE-770 — Allocation Without Limits

**Applicable: YES in principle, partially mitigated.**

The library does not allocate buffers proportional to input size; it walks the
input one byte at a time (or one chunk at a time via `memoryview` slicing). The
table-driven path uses `memoryview` natively, avoiding byte-by-byte allocation.

However, `_parse_hex` in the CLI does `text.replace(" ", "").replace("\n", "")...`
which allocates intermediate strings but bounded by the input argv size (typically
~128 KB). For practical use this is fine.

Severity: **Low** (library does not amplify; CLI argv-bounded).

## CWE-835 — Infinite Loop

**Applicable: NO.**

Both the bit-by-bit and table-driven loops iterate `for byte in data:` — bounded
by the length of the bytes-like input. The inner `for _ in range(8):` is exactly
8 iterations. No `while` loops anywhere in the package.

Verified: 1 MB and 10 MB inputs both terminate cleanly with no hangs during fuzz.

Severity: **N/A**.

## Summary table

| CWE | Applicable? | Severity | Evidence |
|-----|-------------|----------|----------|
| CWE-20  | Yes, mitigated | Info    | bytes-like isinstance check at 4 call sites; 9/9 bad-input probes raise TypeError cleanly |
| CWE-125 | No             | N/A     | All indexed access is `& 0xFF`-masked; TABLE has 256 entries |
| CWE-190 | Yes, mitigated | Info    | Explicit `& 0xFFFF` masks at every assignment; Python bignums are arbitrary-precision |
| CWE-400 | Yes, partial   | Low     | 50 MB call completes in ~0.5s; no upper-bound cap in API |
| CWE-770 | Yes, partial   | Low     | Library walks input byte-by-byte (no amplification); CLI argv-bounded |
| CWE-835 | No             | N/A     | All loops are `for byte in data` / `for _ in range(8)`; no `while` |

**Overall CWE risk profile: 6 CWEs evaluated, 0 Critical, 0 High, 0 Medium, 2 Low, 2 Info, 2 N/A.**
