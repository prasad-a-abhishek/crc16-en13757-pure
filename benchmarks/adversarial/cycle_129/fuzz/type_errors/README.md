# fuzz/type_errors

**Harness**: `harness_type_errors.py`
**Iteration budget**: 50,000
**Kind**: exception

Invariant 21 conformance — 20 canonical bad inputs + randomized fuzz, every surface must raise TypeError (not AttributeError/ValueError).

## Layout

```
fuzz/type_errors/
├── corpus/seed -> ../../corpus/seed  (symlink to shared seed pool)
├── crashes/   (0 expected; .gitkeep placeholder)
├── hangs/     (0 expected; .gitkeep placeholder)
├── oom/       (0 expected; .gitkeep placeholder)
├── logs/run.log
└── stats.json
```
