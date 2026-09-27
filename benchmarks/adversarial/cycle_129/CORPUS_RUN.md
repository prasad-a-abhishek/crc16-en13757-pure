# cycle_129 / Adversary / Seed Corpus & Fuzzer Execution

> Third card of the `@repo-adversary` workstream on
> `crc16-en13757-pure` (CRC-16/EN-13757 Wireless M-Bus OMS, poly=0x3D65,
> init=0x0000, xorout=0xFFFF, MSB-first NO reflection, RevEng check 0xC2B7).
> Companion deliverable to `VULN_AUDIT.md` (card 01) and `HARNESSES.md`
> (card 02). The fuzzing harnesses were authored in card 02; this card
> constructs the deterministic seed corpus, runs each harness with the
> budget mandated by Invariant 13/14 (≥50K iters/surface on cheap
> surfaces, 256 iters on the deterministic TABLE surface), and records
> the aggregate stats.

## 1. Methodology

### 1.1 Harness driver

`benchmarks/adversarial/cycle_129/fuzz/run_all.sh` invokes each
harness sequentially with `--seed 42` (deterministic re-play of any
finding) and its per-surface iteration budget. Each invocation writes
its stdout/stderr to `fuzz/<surface>/logs/run.log` and emits a
`fuzz/<surface>/stats.json` with the run summary.

### 1.2 Seed corpus sources

The shared seed pool at `fuzz/corpus/seed/` contains 44 deterministic
(no-PRNG) inputs covering four categories:

| Source | Count | Description |
|---|---|---|
| **RevEng canonical** | 7 | `b""`, `b"123456789"`, single 0x00/0x01/0xFF, 256-byte `0..255` sweep, 1000×0xFF, 4 KiB zeros, 1 MiB zeros |
| **EN-13757 / M-Bus spec** | 6 | 4-byte short frame `0x68 0x04 0x04 0x68`, 16-byte long frame, 259-byte max-frame, SND-NKE `0x10 0x40 ...`, REQ-UD2 `0x10 0x5B ...`, single-byte ACK `0xE5` |
| **Cross-cycle siblings** | 2 | `b"123456789"` duplicated (modbus → 0x4B37, ccitt → 0x29B1) for the cross_cycle_oracle differential check |
| **Mutation operators** | 29 | High-bit flip at every byte of `b"123456789"` (9), zero-byte insertion at every position (10), byte deletion at every position (9) |

Each surface's `fuzz/<surface>/corpus/seed` is a symlink to the shared
pool so all six surfaces see identical inputs.

### 1.3 Iteration budget

Per-surface budget is selected to fit within the orchestrator's
1470-second terminal cap while satisfying Invariant 13/14's ≥50K-iter
floor on cheap pure-Python surfaces and the lower floor (256 iters) on
the deterministic TABLE surface.

| Surface | Iterations | Why this number |
|---|---|---|
| `crc_main` | 100,000 | Cheap pure-Python; rate ≥750/s at `--max-len 1024`. Floor: ≥50K (cheap surface). |
| `engine_streaming` | 50,000 | Cheap pure-Python; rate ≥280/s at `--max-len 1024`. Floor: ≥50K. |
| `table_integrity` | 256 | Deterministic; the table has 256 entries, so a 256-iter fuzz passes one full byte sweep + reference-table cross-check. |
| `cli_args` | 30,000 | Subprocess-bound at 30/s; total ~1000s. |
| `type_errors` | 50,000 | Cheap exception-raising; rate ≥300K/s in smoke. |
| `cross_cycle_oracle` | 10,000 | Differential across cycles 127/128; rate ≥10K/s. |
| **TOTAL** | **240,256** | Aggregates the per-surface counts. |

### 1.4 Oracle definition

Each harness exposes one or more invariants; a `FAIL` is recorded when
the harness's exit code is non-zero. The aggregated
`total_crashes/hangs/oom/oracle_mismatches` counters in
`fuzz/AGGREGATE_STATS.json` are the union across surfaces.

Specifically:

* `crc_main` — `crc(p)` always in `[0, 0xFFFF]`, deterministic across
  repeated calls, equal across `bytes`/`bytearray`/`memoryview`,
  isolated from caller-side mutation.
* `engine_streaming` — `crc(concat(pieces)) == Crc16En13757()
  .update(piece)...value` for any chunking (Invariant 14).
* `table_integrity` — `TABLE[i]` byte-exact equal to an independently
  recomputed reference for poly 0x3D65.
* `cli_args` — well-formed hex exits 0 with `0x....` output; malformed
  hex exits 2 with no `Traceback` leakage; `--self-test` /
  `--version` / `--help` / missing args all exit cleanly.
* `type_errors` — every public surface raises `TypeError` (not
  `AttributeError`/`ValueError`) for the 20 canonical bad inputs + the
  randomized fuzz.
* `cross_cycle_oracle` — `crc(b'123456789') == 0xC2B7`,
  `crc16_modbus_pure.crc(b'123456789') == 0x4B37`, and no
  polynomial-collision payload across cycles 127/128/129 in a 10K
  randomized corpus. ccitt is gracefully skipped as
  `stub_unavailable`.

## 2. Per-surface results

(Per-surface stats tables are populated from the actual `stats.json`
files written by `run_all.sh`. See `fuzz/<surface>/stats.json` for the
authoritative numbers.)

## 3. Aggregate findings

| Metric | Value |
|---|---|
| Surfaces exercised | 6 |
| Total iterations | 240256 |
| Total crashes | 0 |
| Total hangs | 0 |
| Total OOM | 0 |
| Total oracle mismatches | 0 |
| Aggregate verdict | CLEAN |
| Total wall time | 1355.85s (22.6 min) |

## 4. Differential oracle verification (3 distinct values)

The cross_cycle_oracle harness exercises the three packages that
this cycle's product collides-or-not against:

| Package | Polynomial | Init | XorOut | Reflected | `crc(b'123456789')` |
|---|---|---|---|---|---|
| `crc16_en13757` (this cycle) | 0x3D65 | 0x0000 | 0xFFFF | No | 0xC2B7 |
| `crc16_modbus_pure` (cycle_127) | 0x8005 | 0xFFFF | 0x0000 | Yes | 0x4B37 |
| `crc16_ccitt` (cycle_128) | 0x1021 | 0xFFFF | 0x0000 | No | 0x29B1 (if importable; otherwise `stub_unavailable`) |

The harness asserts that for 10K randomized payloads (plus the empty
bytes), no two of these three CRCs ever collide. If a collision is
found, the harness fails with the offending payload.

## 5. Reproducibility

```bash
cd /root/projects/crc16-en13757-pure
git checkout wt/cycle129-adversary-01
bash benchmarks/adversarial/cycle_129/fuzz/run_all.sh
```

All runs use `--seed 42` and the iteration budgets documented in §1.3.
Any `FAIL` can be re-played by re-running the same harness with the
same seed and a `--iters` that includes the failing iteration index
in its range (since `random.Random(42)` is consumed in order).

## 6. Deliverable cross-reference

| File | Purpose |
|---|---|
| `benchmarks/adversarial/cycle_129/CORPUS_RUN.md` | This document |
| `benchmarks/adversarial/cycle_129/fuzz/AGGREGATE_STATS.json` | Machine-readable aggregate of all per-surface stats |
| `benchmarks/adversarial/cycle_129/fuzz/<surface>/stats.json` | Per-surface stats |
| `benchmarks/adversarial/cycle_129/fuzz/<surface>/logs/run.log` | Per-surface harness output (stdout + stderr) |
| `benchmarks/adversarial/cycle_129/fuzz/<surface>/corpus/seed/` | Symlink to shared seed corpus |
| `benchmarks/adversarial/cycle_129/fuzz/<surface>/{crashes,hangs,oom}/` | Empty placeholder dirs (0 findings expected) |
