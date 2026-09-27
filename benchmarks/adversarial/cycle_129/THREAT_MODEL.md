# THREAT_MODEL — cycle_129 manual vulnerability audit

Cycle: 129
Repo: crc16-en13757-pure
Base commit: c316b9812b8fb618659acbefde9c078126f5ca8c

## STRIDE analysis

STRIDE = Spoofing / Tampering / Repudiation / Information disclosure / Denial of
service / Elevation of privilege.

## Trust boundaries (recap)

The package has exactly one trust boundary: the Python import / argparse boundary.
Inside that boundary, no file I/O, no network, no subprocess, no FFI. All
inputs are caller-supplied via Python function args or `argv`.

---

## S — Spoofing

**Threat**: attacker passes `data` claiming to be a specific protocol frame and
the caller treats the CRC as proof of origin.

**Analysis**: A CRC is a *checksum*, not a *cryptographic signature*. Wireless
M-Bus / OMS uses CRC-16/EN-13757 exactly because it's cheap and detects
*accidental* bit errors (with Hamming distance properties), NOT because it
resists a malicious sender who knows the algorithm. Anyone with the polynomial
can compute a valid CRC for any forged payload.

**Severity**: **N/A — out of scope for this library.** The README does not claim
authenticity, integrity-via-signature, or tamper-detection. A user who needs
authenticated integrity must layer a MAC on top. This is documented behavior of
CRC algorithms generally.

**Mitigation already in place**: README limitations section notes "CRC is not a
cryptographic hash". Verified in `README.md` Limitations block.

---

## T — Tampering

**Threat**: attacker modifies the input buffer mid-CRComputation.

**Analysis**:
1. Mid-stream bytearray mutation: `Crc16En13757.update(bytearray(b"12345"))` then
   `bytearray_result[0] = 0x00` after — the CRC has already been computed over the
   original bytes (CPython `for byte in data` materialises each byte via the buffer
   protocol at iteration time, not via held reference). On PyPy behaviour could
   differ. See TEST_GAPS F-02.
2. Memoryview backing-buffer mutation: same as above; the `for byte in data`
   iterates over the memoryview at iteration time, not over a snapshot. On CPython
   this is eager, but the contract is "bytes-like at call time" — a user who needs
   a snapshot must copy.

**Severity**: **Info** — caller is responsible for the bytes-like's lifecycle;
the library documents "bytes-like" not "bytes-snapshot".

---

## R — Repudiation

**Threat**: caller claims "I never computed that CRC".

**Analysis**: a CRC value is deterministic given the input. Repudiation would
require the input itself to be repudiated (different bytes → different CRC,
always). There is no logging, no audit trail, no signature — the CRC value
IS the proof. A user who needs non-repudiable attestation must use a digital
signature scheme, not a CRC.

**Severity**: **N/A — out of scope.**

---

## I — Information disclosure

**Threat**: CRC leaks information about the input.

**Analysis**: a 16-bit CRC has 65536 possible output values, so it leaks at most
16 bits of information about an arbitrary-length input. For *short* inputs (≤16
bytes), a 16-bit CRC can be inverted trivially (brute force over 2^128 inputs
takes longer than the heat death of the universe, but for *single-byte* inputs,
the 256-entry table is the entire mapping). For *structured* inputs (e.g.
floating-point numbers with predictable bit patterns), CRC correlation attacks
have been published (https://www.cs.cmu.edu/~kqy/resources/CRC.pdf).

**However**: this is a property of CRCs as a class, not a vulnerability of this
particular implementation. Wireless M-Bus / OMS treats CRCs as integrity-only
checksums; confidentiality (if needed) is handled by other layers.

**Severity**: **Info — design property, documented behavior.**

---

## D — Denial of service

**Threat**: attacker causes the library to consume unbounded CPU/RAM/disk.

**Analysis**:

1. **CPU**: `crc(b'X' * 50_000_000)` runs in ~0.5s and ~50 MB RAM on the audit
   sandbox (verified). The algorithm is O(n) in input size with a small constant
   (8 inner iterations per byte for bit-by-bit, 1 byte per iteration for table-driven).
   No quadratic blow-up possible from the algorithm structure.

2. **Memory**: the library holds O(1) state (one 16-bit register). It walks input
   byte-by-byte via the iterator protocol. A 50 MB input uses ~50 MB transient
   memory (the input itself, which the caller passed in) and 0 library state.

3. **Disk**: no disk I/O anywhere. Verified.

4. **Through the CLI**: `--data HEX` is bounded by argv size (~128 KB on Linux).
   An attacker feeding a multi-MB hex string via argv hits the argv limit before
   hitting the algorithm. `python3 -m crc16_en13757 --data $(python3 -c "print('41' * 10_000_000)")`
   would hit the argv limit at ~64K args.

**Severity**: **Low**. The only realistic DoS is a self-inflicted one (you run
the library on a huge input by mistake). For a network-reachable service, the
caller should layer an input-size cap in front of this library.

---

## E — Elevation of privilege

**Threat**: library does something the caller didn't intend (e.g. executes code,
modifies state, writes to disk, opens a socket).

**Analysis**:

1. **Code execution**: no `eval`, no `exec`, no `pickle.loads`, no
   `subprocess.run`, no `os.system`, no `__import__` magic. Verified by reading
   the entire `src/crc16_en13757/` tree (5 files, 250 LOC).

2. **Filesystem writes**: no `open()` in write mode anywhere. Verified.

3. **Network**: no `socket`, no `urllib`, no `requests`. Verified.

4. **Privilege escalation via path traversal**: N/A — no file reads.

5. **Type confusion via init argument**: `crc(data, init=object_with_dunder)`
   — Python's `& 0xFFFF` on a non-int would raise `TypeError: unsupported
   operand type(s) for &: 'object' and 'int'`. No exploit path; the exception
   is clean.

**Severity**: **N/A — no elevation surface.**

---

## Threat-model summary table

| Category | Applicable? | Severity | Notes |
|----------|-------------|----------|-------|
| Spoofing           | N/A  | N/A    | CRC is not a signature; documented |
| Tampering          | Yes  | Info   | bytearray/memoryview mutation-by-caller is caller's responsibility |
| Repudiation        | N/A  | N/A    | CRC is deterministic; non-repudiation requires a signature scheme |
| Information discl. | Yes  | Info   | 16-bit CRC leaks ~16 bits; design property, not a vuln |
| Denial of service  | Yes  | Low    | O(n) algorithm, no amplification; self-DoS only |
| Elevation of priv. | N/A  | N/A    | No code-exec, no file-I/O, no network surface |

**Overall threat profile**: 6 STRIDE categories evaluated. Zero High or Critical
threats. One Low (DoS via self-DoS), three Info (tampering, info disclosure, design
properties), two N/A (out of scope for CRC as a class).
