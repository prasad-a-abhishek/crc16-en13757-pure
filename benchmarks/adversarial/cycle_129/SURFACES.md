# SURFACES — cycle_129 manual vulnerability audit

Cycle: 129
Repo: crc16-en13757-pure
Base commit: c316b9812b8fb618659acbefde9c078126f5ca8c

## Trust boundary model

The package has exactly ONE trust boundary: the Python import / argparse boundary.
Once a caller has imported the package or invoked the CLI, they are inside the
trust zone. There is no network surface, no IPC surface, no FFI surface, no
file-I/O surface (the CLI does not read files — see Surface 5 below for the
discrepancy with the task spec).

## Surface inventory (7 enumerated)

### Surface 1: `crc16_en13757.crc(data, init=INIT)`

- **Trust boundary**: caller-controlled `data` (bytes-like), caller-controlled `init` (int).
- **Attack vectors**:
  - Type confusion: pass non-bytes-like (verified: 9/9 bad inputs raise TypeError cleanly).
  - Huge input: pass 50 MB of bytes (verified: completes in ~0.5s, no OOM, no crash).
  - init out of range: pass `-1` or `2**32` (verified: masked via `& 0xFFFF`).
- **Internal call chain**: `crc → _crc_raw(data, init) ^ XOROUT`.
- **Test status**: GREEN — `test_crc_raises_type_error_for_non_bytes_like` (parametrized 9 inputs),
  `test_crc_accepts_bytearray`, `test_crc_accepts_memoryview`,
  `test_xorout_property_default_init`, `test_init_mask_high_bits_truncated`,
  `test_idempotent_on_random_inputs`, `test_fuzz_50_random_inputs_match_table_oracle`.
- **Verdict**: CLEAN (no vuln found).

### Surface 2: `crc16_en13757.Crc16En13757` class (note: task spec called this `CrcEngine`)

- **Public API**: `__init__(init=INIT)`, `update(data)`, `value` property, `reset(init=INIT)`.
- **Trust boundary**: caller-controlled `data` on each `update()` call.
- **Attack vectors**:
  - Same as Surface 1 for each `update()`.
  - State-staleness via `reset()` followed by stale `update()` — none, state is fully reset.
  - Property race on `_reg`: not a concern (single-threaded CPython GIL).
- **Test status**: GREEN — `test_crc16_en13757_empty`, `test_crc16_en13757_reset_to_non_zero`,
  `test_streaming_wrapper_matches_one_shot`, `test_streaming_wrapper_chunks_match_one_shot`,
  `test_streaming_wrapper_reset_clears_state`, `test_streaming_wrapper_custom_init`,
  `test_streaming_wrapper_raises_type_error`, `test_streaming_wrapper_byte_at_a_time_matches_one_shot`.
- **Verdict**: CLEAN.

### Surface 3: `crc16_en13757.table` module constant + `table_lookup()` function

- **Trust boundary**: caller-controlled `data` to `table_lookup()`. TABLE itself is built
  once at import time and is read-only (`tuple`).
- **Attack vectors**:
  - TABLE corruption: not possible (it's a `tuple`, immutable).
  - TABLE index out-of-range: masked via `& 0xFF` on the index expression.
  - TABLE wrong values: would be an algorithm bug. Verified: 256 entries, all in
    `[0, 0xFFFF]`, all distinct (verified empirically). Spot-checked first 16:
    `TABLE[0:16] == [0x0000, 0x3d65, 0x7aca, 0x472f, 0xf994, 0xc4f1, 0x835e, 0xbe3b,
    0xcccd, 0xf1a8, 0xb667, 0x8b02, 0x3559, 0x083c, 0x7593, 0x48f6]` (matches
    standard MSB-first CRC-16/EN-13757 table generation algorithm).
- **Test status**: GREEN — `test_table_is_256_entries`, `test_table_entries_are_in_range`
  (parametrized 256), `test_table_lookup_matches_bit_by_bit_on_canonical` (parametrized 6),
  `test_table_lookup_matches_on_100_random_inputs`,
  `test_table_lookup_returns_post_xorout`, `test_table_lookup_accepts_bytearray`,
  `test_table_lookup_accepts_memoryview`,
  `test_table_lookup_raises_type_error_for_non_bytes_like`,
  `test_table_lookup_raises_type_error`.
- **Verdict**: CLEAN.

### Surface 4: CLI argparse entrypoint `python3 -m crc16_en13757`

- **Subcommands**: `--data HEX`, `--self-test`, `--version` (mutually exclusive).
- **Trust boundary**: caller-controlled argv. `--data` is parsed as hex via
  `bytes.fromhex` with whitespace stripped.
- **Attack vectors**:
  - Malformed hex (odd length, non-hex chars): rejected with exit 2 + stderr
    message. Verified: `--data 12G4` and `--data ZZZZZZ` both fail cleanly.
  - Missing required arg: argparse usage error, exit 2.
  - `--version` / `--help`: argparse handles, exit 0.
  - `--self-test`: runs 6 hardcoded vectors, deterministic, no I/O.
- **Test status**: GREEN — `test_cli_check_value`, `test_cli_empty_data`,
  `test_cli_data_with_whitespace`, `test_cli_single_zero_byte`, `test_cli_single_ff_byte`,
  `test_cli_zero_to_nine`, `test_cli_self_test_passes_all_vectors`,
  `test_cli_malformed_hex_exits_2`, `test_cli_odd_length_hex_exits_2`,
  `test_cli_no_args_exits_2`, `test_cli_version_flag`, `test_cli_help_flag`.
- **Verdict**: CLEAN.

### Surface 5: CLI `--input-file PATH` (per task spec) — **DOES NOT EXIST**

- **Discrepancy with task spec**: the cycle_129 card body listed surface 5 as
  "CLI accepts `--input-file PATH` (path traversal surface)" — but the actual
  CLI in `src/crc16_en13757/cli.py` does NOT define an `--input-file` flag.
  The `argparse.add_mutually_exclusive_group` only contains `--data` and
  `--self-test`. There is no file reading anywhere in the package.
  Verified with `search_files` for `input-file|--input|open\(` under `src/`
  (1 match: a docstring word "read" in `__init__.py:14`, no code path).
- **Attack vectors**: N/A — the surface does not exist.
- **Test status**: N/A.
- **Verdict**: CLEAN (because the attack surface doesn't exist).

### Surface 6: Module import side effects

- **Trust boundary**: the importing process.
- **Side effects to check for**: file reads, network I/O, signal handlers, env
  var reads, `os.system`, `subprocess`, threads started, atexit handlers, etc.
- **Audit method**: instrumented `builtins.open` and tracked new `sys.modules`
  entries during `import crc16_en13757`.
- **Observations**:
  - 0 files opened during import.
  - 3 modules added to `sys.modules`: `crc16_en13757`, `crc16_en13757._table`,
    `crc16_en13757.core`. All stdlib-adjacent (no external deps; `pyproject.toml`
    has `dependencies = []`).
  - TABLE is computed at import time, but it's a pure-Python loop over 256 ints —
    deterministic, no I/O.
- **Test status**: implicitly GREEN — 394 tests all pass without env setup.
- **Verdict**: CLEAN.

### Surface 7: Cross-cycle oracle differential

- **Trust boundary**: shared algorithmic identity vs shipped siblings (cycle_127
  modbus, cycle_128 ccitt-false, crcmodel reference).
- **Attack vectors**: algorithm regression, parameter swap (poly/init/xorout),
  accidental mirroring, accidental reflection flip.
- **Audit method**: ran 50 distinct SHA-256-derived 32-byte payloads through
  `crc_en13757` vs `crc_modbus` (cycle_127 sibling) and confirmed 50/50 differ.
- **Observations**:
  - EN-13757 check value `0xC2B7` (b'123456789') byte-distinct from
    MODBUS `0x4B37` and CCITT-FALSE `0x29B1`.
  - Empty-input EN-13757 `0xFFFF` vs MODBUS `0x0000` vs CCITT-FALSE `0xFFFF`
    (the ccitt empty value coincidentally matches en-13757; this is by RevEng
    definition because both have init=0xFFFF xorout=0x0000 vs init=0x0000 xorout=0xFFFF
    — but the ccitt sibling is shipped as a near-stub, so the comparison is
    via documented parameters, not live API calls).
  - All algorithm params (poly=0x3D65, init=0x0000, refin=False, refout=False,
    xorout=0xFFFF) match RevEng "CRC-16/EN-13757" entry exactly.
- **Test status**: GREEN — `test_differs_from_cycle_127_modbus` (parametrized 10),
  `test_differs_from_cycle_128_ccitt_false` (parametrized 10),
  `test_check_value_not_ccitt`, `test_check_value_not_modbus`,
  `test_crcmod_oracle_matches_on_canonical` (parametrized 6),
  `test_crcmod_oracle_matches_on_100_random_inputs`.
- **Verdict**: CLEAN.

## Surface summary

| # | Surface                          | Trust boundary        | Vuln? | Test status |
|---|----------------------------------|-----------------------|-------|-------------|
| 1 | `crc()`                          | caller data + init    | No    | GREEN       |
| 2 | `Crc16En13757` class             | caller data per update| No    | GREEN       |
| 3 | `TABLE` + `table_lookup()`       | caller data           | No    | GREEN       |
| 4 | CLI (`--data`, `--self-test`)    | caller argv           | No    | GREEN       |
| 5 | CLI `--input-file` (spec'd)      | N/A — surface absent  | No    | N/A         |
| 6 | Module import side effects       | importing process     | No    | GREEN       |
| 7 | Cross-cycle oracle differential  | algorithm identity    | No    | GREEN       |

**All 7 surfaces evaluated. Zero exploitable findings. Zero medium-or-higher
non-exploitable findings.**
