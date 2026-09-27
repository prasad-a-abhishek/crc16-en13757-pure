# fuzz/crc_main

**Harness**: `harness_crc_main.py`
**Iteration budget**: 100,000
**Kind**: deterministic

Main crc() single-shot entry point — determinism, view equivalence, mutation isolation, output range.

## Layout

```
fuzz/crc_main/
├── corpus/seed -> ../../corpus/seed  (symlink to shared seed pool)
├── crashes/   (0 expected; .gitkeep placeholder)
├── hangs/     (0 expected; .gitkeep placeholder)
├── oom/       (0 expected; .gitkeep placeholder)
├── logs/run.log
└── stats.json
```
