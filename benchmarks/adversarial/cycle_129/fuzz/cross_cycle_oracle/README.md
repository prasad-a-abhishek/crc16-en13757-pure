# fuzz/cross_cycle_oracle

**Harness**: `harness_cross_cycle_oracle.py`
**Iteration budget**: 10,000
**Kind**: differential

Differential oracle across cycles 127 (modbus 0x4B37) and 128 (ccitt 0x29B1) — must NOT collide with en13757 0xC2B7.

## Layout

```
fuzz/cross_cycle_oracle/
├── corpus/seed -> ../../corpus/seed  (symlink to shared seed pool)
├── crashes/   (0 expected; .gitkeep placeholder)
├── hangs/     (0 expected; .gitkeep placeholder)
├── oom/       (0 expected; .gitkeep placeholder)
├── logs/run.log
└── stats.json
```
