# fuzz/cli_args

**Harness**: `harness_cli_args.py`
**Iteration budget**: 30,000
**Kind**: argv

python3 -m crc16_en13757 CLI surface — well-formed hex, malformed hex, missing args, --self-test, --version, --help, no Traceback leakage.

## Layout

```
fuzz/cli_args/
├── corpus/seed -> ../../corpus/seed  (symlink to shared seed pool)
├── crashes/   (0 expected; .gitkeep placeholder)
├── hangs/     (0 expected; .gitkeep placeholder)
├── oom/       (0 expected; .gitkeep placeholder)
├── logs/run.log
└── stats.json
```
