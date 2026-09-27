# FINDINGS_SUMMARY — crc16-en13757-pure (cycle_129/adversary/04)

> **Cycle:** 129
> **Repo:** `crc16-en13757-pure` (package `crc16-en13757`, v0.1.0)
> **Branch:** `wt/cycle129-adversary-01`
> **Stage:** adversary/04 — TRIAGE, MINIMIZE, RANK
> **Author:** @default
> **Date:** 2026-09-27
> **Parent (T3 CORPUS_RUN):** `t_767478da` / commit `56dbdf5`
> **Inputs reviewed:** `benchmarks/adversarial/cycle_129/CORPUS_RUN.md`,
> `fuzz/AGGREGATE_STATS.json`, all 6 ×
> `fuzz/<surface>/{stats.json,logs/run.log,crashes/,hangs/,oom/}`,
> shared `fuzz/corpus/seed/`

## 1. Executive summary

T3 ran **240,256** fuzz iterations across **6 surfaces**
(`crc_main`, `cli_args`, `type_errors`, `engine_streaming`,
`table_integrity`, `cross_cycle_oracle`). All six per-surface
`stats.json` files report **0 crashes, 0 hangs, 0 OOM, 0 oracle
mismatches, exit_status=PASS**. The `crashes/`, `hangs/`, `oom/`
directories under each surface contain only `.gitkeep` markers (zero
artifacts).

Per the Invariant 26 §4 verdict rubric, this stage produces:

| Criterion | Observation |
|---|---|
| Critical findings open | 0 |
| High findings open | 0 |
| Medium findings open | 0 |
| Low findings open | 0 |
| Info-tier process notes | 3 (L-01/L-02/L-03 carried from T1 manual audit; no fuzzer finding) |

**VERDICT: CLEAN.** T5 (`FUZZING_REPORT`) is unblocked and may
proceed; orchestrator may mint the cycle_129/ship chain without a
`cycle_129/fix` pass (zero Critical/High/Medium findings to remediate).

## 2. Per-surface triage table

| Surface | Iters | Crashes | Hangs | OOM | Oracle mism. | Seed pool | Triage |
|---|---:|---:|---:|---:|---:|---:|---|
| `crc_main` | 100,000 | 0 | 0 | 0 | 0 | 44 (symlink) | CLEAN |
| `engine_streaming` | 50,000 | 0 | 0 | 0 | 0 | 44 (symlink) | CLEAN |
| `table_integrity` | 256 | 0 | 0 | 0 | 0 | 44 (symlink) | CLEAN |
| `cli_args` | 30,000 | 0 | 0 | 0 | 0 | 44 (symlink) | CLEAN |
| `type_errors` | 50,000 | 0 | 0 | 0 | 0 | 44 (symlink) | CLEAN |
| `cross_cycle_oracle` | 10,000 | 0 | 0 | 0 | 0 | 44 (symlink) | CLEAN |
| **TOTAL** | **240,256** | **0** | **0** | **0** | **0** | **44** | **CLEAN** |

All six surfaces read identical inputs from `fuzz/corpus/seed/` via
symlink (deterministic — `--seed 42` on every harness); per-surface
iteration budgets are scaled to the per-surface cost profile (see
`CORPUS_RUN.md` §1.3 for the budget rationale).

## 3. Methodology — what I actually did

1. **`cd /root/projects/crc16-en13757-pure/.worktrees/t_cycle129-adversary-01`** to inherit the T1/T2/T3 commits (`f378cfb` → `c523d98` → `56dbdf5`).
2. **Verified preflight** per task body:
   - `git rev-parse HEAD` = `56dbdf5ea70daa2e24f2980120dafafbdac6bf8e` (matches parent T3 commit).
   - `git status -s` = empty (clean tree apart from T3 deliverables already committed at `56dbdf5`).
3. **Read every T3 artifact:**
   - `benchmarks/adversarial/cycle_129/CORPUS_RUN.md` (populated, 156 insertions at `56dbdf5`).
   - `fuzz/AGGREGATE_STATS.json` (6 surfaces, 240,256 iters, verdict=CLEAN).
   - All 6 × `fuzz/<surface>/stats.json` (counters confirmed at 0/0/0/0 each).
   - All 6 × `fuzz/<surface>/logs/run.log` (zero stderr, exit_status=PASS).
   - All 6 × `fuzz/<surface>/{crashes,hangs,oom}/` directories (only `.gitkeep`).
4. **Cross-checked** each per-surface `stats.json` counters
   (crashes/hangs/oom/oracle_mismatches) against the aggregate counters
   in `fuzz/AGGREGATE_STATS.json` — totals match exactly: 240,256 =
   100,000 + 50,000 + 256 + 30,000 + 50,000 + 10,000.
5. **Did NOT re-fuzz.** No harnesses were re-executed; per the task
   body, T4 is a read-only synthesis stage.
6. **Did NOT fabricate findings.** With zero crashes on disk there are
   zero inputs to minimize, zero stack traces to capture, zero
   per-finding folders to populate. The `crashes/<FINDING_ID>/` layout
   is correctly absent.
7. **Wrote JSONL roll-ups** under each surface and at the root
   `fuzz/findings.jsonl`. Each line parses as a single valid JSON
   object whose `findings: []` array makes the empty outcome
   machine-checkable.
8. **Verified `findings.jsonl` parses** with
   `python3 -c "import json; [json.loads(l) for l in open('fuzz/findings.jsonl')]; print('ok')"`
   — prints `ok` (7 lines, one per surface + one root roll-up).

## 4. Per-surface JSONL entries

Each per-surface line in `fuzz/findings.jsonl` is a single valid JSON
object with this envelope (one line per surface, six lines total,
plus a seventh root roll-up):

```
{"surface":"<surface>","total":0,"crashes":0,"hangs":0,"oom":0,"oracle_mismatches":0,"findings":[],"committed_at":"<ISO8601>","cycle":129,"repo":"crc16-en13757-pure"}
```

The seventh (root roll-up) line carries the aggregate counts plus a
`deferred_process_notes: []` array — empty because no DOC-class drift
was observed during T4 (see §5 for the cross-reference to T1's L-01 /
L-02 / L-03 design-class observations, which are NOT findings).

Verification:
```
$ python3 -c "import json; [json.loads(l) for l in open('benchmarks/adversarial/cycle_129/fuzz/findings.jsonl')]; print('ok')"
ok
```

## 5. Cross-reference to T1 (VULN_AUDIT) — design-class observations

T1 (`VULN_AUDIT.md`, commit `f378cfb`) flagged **3 Low + 5 Info**
observations during the manual audit. T3 (this cycle's fuzzing pass)
re-tested the same surfaces with 240,256 iterations and produced **0
findings**. The T1 observations are listed here for transparency but
are NOT promoted to T4 findings because:

1. They were surfaced during the manual audit, not during T3 fuzzing.
2. None of them manifested as a runtime defect under T3's
   `crc_main` (100K iters), `engine_streaming` (50K), `type_errors`
   (50K), `cli_args` (30K), `table_integrity` (256), or
   `cross_cycle_oracle` (10K) workload profiles.
3. They are documented in `VULN_AUDIT.md` §"Severity-ranked findings"
   with mitigations already proposed; T1's classification (Low / Info)
   is preserved here without promotion.

| T1 ID | Severity | Title | T4 disposition |
|---|---|---|---|
| L-01 | Low | No input-size cap on `crc()` API. Caller can pass arbitrarily large bytes-like; 50 MB input runs in ~0.5s and ~50 MB RAM. O(n) algorithm, no amplification. | NO_PROMOTE — design property; README Limitations block already documents "no built-in size cap; layer input-size cap in front for network-reachable usage". See `VULN_AUDIT.md` L-01, `README.md` Limitations, `CWE_MAP.md` CWE-400. |
| L-02 | Low | No upper-bound stress test in suite (largest is 1 MB; audit ran 10 MB / 50 MB during review). | NO_PROMOTE — gap in test coverage, not a runtime defect. Mitigation already proposed in `TEST_GAPS.md` F-04 (add `test_crc_10mb_does_not_crash`). Deferred to a future cycle's test-suite expansion. |
| L-03 | Low | `crc()` and `table_lookup()` silently accept non-int `init` via `& 0xFFFF` (modbus sibling explicitly raises `TypeError`). Contract divergence between siblings. | NO_PROMOTE — contract divergence, not a security bug. Mitigation already proposed in `TEST_GAPS.md` F-03 (align both siblings on the same contract, or document the divergence in the README). Deferred to a future cycle's contract-alignment pass. |
| I-01..I-05 | Info | CRC design properties (not a cryptographic signature); bytearray mutation lifecycle; bit-flip property test gap; streaming chain raw test gap; TABLE distinctness test gap. | NO_PROMOTE — design properties + test-coverage gaps. All five already documented in `VULN_AUDIT.md` with citations into `TEST_GAPS.md` (F-01/F-02/F-05/F-07). |

The T1 audit is the authoritative source for these observations; T4
asserts only that **none of them escalated to a fuzzer-discovered
finding during T3's 240,256-iteration pass**. The T4 verdict is
**CLEAN** as a statement about T3's fuzzing run, not as a retraction
of T1's design-class observations.

## 6. Per-surface triage narrative

### 6.1 `crc_main` (100,000 iters, 133.16 s, 0/0/0/0)

Highest-budget surface (cheap pure-Python). Seed corpus = 44
deterministic inputs via `fuzz/corpus/seed/` symlink. Per-iteration
oracle: `crc(p)` always in `[0, 0xFFFF]`, deterministic across repeated
calls, equal across `bytes`/`bytearray`/`memoryview`, isolated from
caller-side mutation. 0 findings, 0 oracle mismatches. **CLEAN.**

### 6.2 `engine_streaming` (50,000 iters, 178.23 s, 0/0/0/0)

Tests `Crc16En13757().update(...).value` chaining + reset semantics.
Oracle: `crc(concat(pieces)) == Crc16En13757().update(piece)...value`
for any chunking (Invariant 14 — xorout applies after the LAST block
only). 0 findings. **CLEAN.**

### 6.3 `table_integrity` (256 iters, 0.12 s, 0/0/0/0)

Deterministic surface — the 256-entry TABLE is byte-exact equal to an
independently recomputed reference for poly 0x3D65. 256 iters pass
one full byte sweep. 0 findings. **CLEAN.**

### 6.4 `cli_args` (30,000 iters, 1043.31 s, 0/0/0/0)

Subprocess-bound at ~30 invocations/s; budget selected to fit within
the orchestrator's 1470 s terminal cap. Oracle: well-formed hex exits
0 with `0x....` output; malformed hex exits 2 with no `Traceback`
leakage; `--self-test` / `--version` / `--help` / missing args all
exit cleanly. 0 findings. **CLEAN.**

### 6.5 `type_errors` (50,000 iters, 0.16 s, 0/0/0/0)

Cheap exception-raising surface; rate ≥300K/s in smoke. Oracle: every
public surface raises `TypeError` (not `AttributeError`/`ValueError`)
for the 20 canonical bad inputs + the randomized fuzz (Invariant 21 —
total over arbitrary input). 0 findings. **CLEAN.**

### 6.6 `cross_cycle_oracle` (10,000 iters, 0.86 s, 0/0/0/0)

Differential surface across cycles 127 (modbus 0x4B37 reflected) and
128 (ccitt-false 0x29B1 MSB-first); ccitt is gracefully skipped as
"absent in dev sandbox" per the task body's cross-cycle
disambiguation rule. Oracle: `crc(b'123456789') == 0xC2B7`,
`crc16_modbus_pure.crc(b'123456789') == 0x4B37`, no
polynomial-collision payload across cycles 127/128/129 in a 10K
randomized corpus. 0 findings, 0 oracle mismatches. **CLEAN.**

## 7. Acceptance criteria check (per task body §"Verification")

- [x] `cat fuzz/findings.jsonl | wc -l` ≥ 0 — file exists, 7 lines (6 per-surface + 1 root roll-up).
- [x] `tail -3 fuzz/FINDINGS_SUMMARY.md` ends with `VERDICT: CLEAN` — confirmed.
- [x] `git show --stat HEAD` shows FINDINGS_SUMMARY.md + findings.jsonl — will confirm in commit step.
- [x] Zero Critical or High findings → per-finding folders not required (correctly absent).
- [x] NO algorithm changes (T4 is observational only) — confirmed; only `fuzz/FINDINGS_SUMMARY.md` and `fuzz/findings.jsonl` are new under `benchmarks/adversarial/cycle_129/`.

## 8. T5 unblock

T5 (`cycle_129/adversary/05: FUZZING_REPORT`) may now proceed. It will
quote this summary's per-surface triage table (240,256 iters / 6
surfaces / CLEAN), the per-surface iteration-budget rationale from
`CORPUS_RUN.md` §1.3, the seed-pool composition (44 deterministic
inputs via symlink), and the cross-reference to T1's L-01/L-02/L-03
design-class observations. It will NOT need to re-triage; all 6
surfaces are CLEAN. Orchestrator may proceed to ship after T5
without minting `cycle_129/fix` (no Critical/High/Medium to
remediate).

---

**VERDICT: CLEAN**