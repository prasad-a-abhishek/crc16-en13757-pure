# CRC-16/EN-13757 — Benchmark Results

50 iterations (10 workload profiles × 5 runs each), byte-payload fuzz
with deterministic seed `20260927`. Lower is better.

## Environment

- OS: Linux-6.12.67-linuxkit-aarch64-with-glibc2.41
- Python: 3.11.15 (CPython)
- CPU: unknown
- Date: 2026-09-27

## Methodology

- Wall-clock measured with `time.perf_counter()` (single-shot per iter).
- Peak RSS measured with `tracemalloc.get_traced_memory()`.
- 10 workload lengths: 16 B, 64 B, 256 B, 1 KiB, 4 KiB, 16 KiB,
  64 KiB, 256 KiB, 1 MiB, 4 MiB.
- 5 iterations per workload per implementation.
- Each iteration runs the implementation once on a fresh random payload
  of the same length (no warm-up reuse; cache effects amortized across iters).
- Random payloads are generated with `random.Random(20260927)` for
  byte-exact reproducibility on any host.

## Results — Mean wall-clock (microseconds) / Peak RSS (KiB)

| Length   | bit-by-bit (ours)   | table-driven (ours) | crcmod (if installed) |
|----------|---------------------|--------------------|-----------------------|
|      16 B |      198.8 µs / 0 KiB |       28.0 µs / 0 KiB |        1.1 µs / 0 KiB |
|      64 B |      790.6 µs / 0 KiB |       59.9 µs / 0 KiB |        1.0 µs / 0 KiB |
|     256 B |     2885.1 µs / 0 KiB |      253.3 µs / 0 KiB |        1.3 µs / 0 KiB |
|    1024 B |    10298.4 µs / 0 KiB |     1000.9 µs / 0 KiB |        4.2 µs / 0 KiB |
|    4096 B |    40445.7 µs / 0 KiB |     3920.9 µs / 0 KiB |        9.8 µs / 0 KiB |
|   16384 B |   162420.7 µs / 0 KiB |    16063.2 µs / 0 KiB |       42.1 µs / 0 KiB |
|   65536 B |   659125.6 µs / 0 KiB |    64324.8 µs / 0 KiB |      153.0 µs / 0 KiB |
|  262144 B |  2625943.0 µs / 0 KiB |   256323.3 µs / 0 KiB |      605.3 µs / 0 KiB |
| 1048576 B | 10653979.0 µs / 0 KiB |  1016259.9 µs / 0 KiB |     2622.4 µs / 0 KiB |
| 4194304 B | 43871477.7 µs / 0 KiB |  4142124.4 µs / 0 KiB |     9902.5 µs / 0 KiB |

## P95 wall-clock (microseconds)

| Length   | bit-by-bit | table-driven | crcmod |
|----------|------------|--------------|--------|
|      16 B |     197.2 |      25.6 |       1.0 |
|      64 B |     793.8 |      61.5 |       1.0 |
|     256 B |    2931.9 |     255.2 |       1.3 |
|    1024 B |   10471.8 |    1010.6 |       3.2 |
|    4096 B |   40596.5 |    3934.2 |       9.7 |
|   16384 B |  163433.9 |   16135.0 |      42.2 |
|   65536 B |  652597.3 |   64673.2 |     154.5 |
|  262144 B | 2628055.0 |  257733.5 |     628.7 |
| 1048576 B | 10673260.0 | 1013735.0 |    2738.0 |
| 4194304 B | 44074498.4 | 4174540.1 |   10286.5 |

## Trade-Offs

- `bit-by-bit` (this package, canonical reference): ~8× per-byte inner loop, but byte-exact and zero-dep. **Use this for correctness work.**
- `table-driven` (this package, `table_lookup`): ~256-entry lookup, same zero-dep guarantee. **Use this for byte-level throughput when crcmod is unavailable.**
- `crcmod` (C extension): fastest. Requires `gcc` at install time. **Use this for production pipelines on commodity Linux.**

## Reproduction

```bash
# From repo root:
python3 benchmarks/run_benchmark.py
```

The script will attempt to `pip install crcmod` if it is not already importable; if that fails, the crcmod column shows `—`.
