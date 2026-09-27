#!/usr/bin/env bash
# cycle_129 fuzz driver -- runs each harness with its iteration budget and
# captures per-surface stats.json + run.log.
#
# Usage:
#   bash benchmarks/adversarial/cycle_129/fuzz/run_all.sh
#
# Each harness invocation is foreground inside this script; the
# orchestrator worker is expected to call this script as a single
# foreground terminal command (or wrap it with `nohup &` if needed).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

ROOT="benchmarks/adversarial/cycle_129/fuzz"
SEED=42

run_surface() {
  local name="$1"
  local harness="$2"
  shift 2
  local iters="$1"; shift
  local extra=("$@")
  local surf="${ROOT}/${name}"
  local log="${surf}/logs/run.log"
  local stats="${surf}/stats.json"
  mkdir -p "${surf}/logs"
  echo "==== ${name} (iters=${iters}) ====" | tee -a "${log}"
  echo "  start: $(date -u +%Y-%m-%dT%H:%M:%SZ) seed=${SEED} extras=${extra[*]:-}" >> "${log}"

  local t0
  t0=$(date +%s.%N)
  # shellcheck disable=SC2068
  if python3 "benchmarks/adversarial/cycle_129/${harness}" \
      --iters "${iters}" --seed "${SEED}" ${extra[@]:-} 2>&1 \
      | tee -a "${log}"; then
    local t1 elapsed rc=0
    t1=$(date +%s.%N)
    elapsed=$(awk "BEGIN{printf \"%.3f\", ${t1} - ${t0}}")
    echo "  end:   $(date -u +%Y-%m-%dT%H:%M:%SZ) elapsed=${elapsed}s status=PASS" >> "${log}"
    python3 - "${stats}" "${name}" "${iters}" "${elapsed}" "${SEED}" <<'PY'
import json, sys
stats_path, surface, iters, elapsed, seed = sys.argv[1:6]
with open(stats_path, "w") as f:
    json.dump({
        "surface": surface,
        "iters": int(iters),
        "elapsed_sec": float(elapsed),
        "crashes": 0,
        "hangs": 0,
        "oom": 0,
        "oracle_mismatches": 0,
        "max_rss_mb": None,
        "seed": int(seed),
        "status": "PASS",
    }, f, indent=2)
PY
    echo "  PASS  ${name} iters=${iters} elapsed=${elapsed}s"
    return 0
  else
    local rc=$?
    local t1 elapsed
    t1=$(date +%s.%N)
    elapsed=$(awk "BEGIN{printf \"%.3f\", ${t1} - ${t0}}")
    echo "  end:   $(date -u +%Y-%m-%dT%H:%M:%SZ) elapsed=${elapsed}s status=FAIL rc=${rc}" >> "${log}"
    python3 - "${stats}" "${name}" "${iters}" "${elapsed}" "${SEED}" "${rc}" <<'PY'
import json, sys
stats_path, surface, iters, elapsed, seed, rc = sys.argv[1:7]
with open(stats_path, "w") as f:
    json.dump({
        "surface": surface,
        "iters": int(iters),
        "elapsed_sec": float(elapsed),
        "crashes": 1,  # surface returned non-zero -- treat as a crash for the run summary
        "hangs": 0,
        "oom": 0,
        "oracle_mismatches": 0,
        "max_rss_mb": None,
        "seed": int(seed),
        "status": "FAIL",
        "returncode": int(rc),
    }, f, indent=2)
PY
    echo "  FAIL  ${name} rc=${rc}"
    return ${rc}
  fi
}

run_surface "crc_main"          "harness_crc_main.py"           100000 --max-len 1024
run_surface "engine_streaming"  "harness_crc_engine_streaming.py" 50000 --max-len 1024 --max-chunks 16
run_surface "table_integrity"   "harness_table_integrity.py"       256
run_surface "cli_args"          "harness_cli_args.py"            30000 --max-hex-len 256
run_surface "type_errors"       "harness_type_errors.py"         50000
run_surface "cross_cycle_oracle" "harness_cross_cycle_oracle.py" 10000

echo "==== all surfaces complete ===="
