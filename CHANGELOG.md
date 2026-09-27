# Changelog

All notable changes to `crc16-en13757` are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/).

## [0.1.0] — 2026-09-27 (cycle_129)

### Added

- **Initial release.**
- Bit-by-bit reference `crc(data, init=0x0000)` matching the RevEng
  catalogue "CRC-16/EN-13757" row (poly=0x3D65, init=0x0000,
  refin=false, refout=false, xorout=0xFFFF, check=0xC2B7).
- `crc_stream(data, init=...)` for chaining CRCs across multi-block
  frames; returns the pre-xorout register state.
- Table-driven `table_lookup(data, init=...)` for benchmarking.
- Object-oriented streaming wrapper `Crc16En13757` with `.update()`
  and `.value`.
- CLI: `python3 -m crc16_en13757 --data <hex>` and `--self-test`.
- 376 pytest items across 9 categories: RevEng vectors,
  byte/length sweeps, cross-cycle disambiguation, table-vs-bit
  equivalence, property tests, CLI, type validation, chunk
  equivalence, fuzz smoke.
- Zero runtime dependencies (standard library only).
- MIT License.

[0.1.0]: https://github.com/prasad-a-abhishek/crc16-en13757/releases/tag/v0.1.0
