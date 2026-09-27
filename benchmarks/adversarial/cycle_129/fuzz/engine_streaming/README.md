# fuzz/engine_streaming

**Harness**: `harness_crc_engine_streaming.py`
**Iteration budget**: 50,000
**Kind**: chunked

Crc16En13757.update() streaming engine — single-shot equality, N-piece chaining, reset round-trip, all-zero 1-byte chunked.

## Layout

```
fuzz/engine_streaming/
├── corpus/seed -> ../../corpus/seed  (symlink to shared seed pool)
├── crashes/   (0 expected; .gitkeep placeholder)
├── hangs/     (0 expected; .gitkeep placeholder)
├── oom/       (0 expected; .gitkeep placeholder)
├── logs/run.log
└── stats.json
```
