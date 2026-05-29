#!/usr/bin/env bash
set -uo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/run_attack_suite.sh [--quick|--standard|--full]

Environment overrides:
  ETAS="1 2 4 8"
  ROUNDS="1 2 4 8 16 32"
  THREADS=auto
  SEED=20260528
  RUN_LATTICE_SOLVER=auto|sage-python|python|none

Sample knobs:
  DIFF_TRIALS DIFF_SEARCHES AVALANCHE_TRIALS WALSH_SAMPLES MI_SAMPLES
  ROTATIONAL_TRIALS STATE_TRACE_SAMPLES HO_SAMPLES LATTICE_SAMPLES
EOF
}

MODE="${ATTACK_SUITE_MODE:-standard}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --quick) MODE="quick" ;;
    --standard) MODE="standard" ;;
    --full) MODE="full" ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

if command -v nproc >/dev/null 2>&1; then
  DEFAULT_THREADS="$(nproc)"
else
  DEFAULT_THREADS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 1)"
fi

ETAS="${ETAS:-1 2 4 8}"
THREADS="${THREADS:-$DEFAULT_THREADS}"
SEED="${SEED:-20260528}"
MESSAGE_LEN="${MESSAGE_LEN:-32}"
STATE_TRACE_MESSAGE_BITS="${STATE_TRACE_MESSAGE_BITS:-512}"
HO_ORDER="${HO_ORDER:-2}"
RUN_LATTICE_SOLVER="${RUN_LATTICE_SOLVER:-auto}"
STRICT_OPTIONAL="${STRICT_OPTIONAL:-0}"

case "$MODE" in
  quick)
    ROUNDS="${ROUNDS:-1 2 4}"
    DIFF_TRIALS="${DIFF_TRIALS:-8}"
    DIFF_SEARCHES="${DIFF_SEARCHES:-16}"
    AVALANCHE_TRIALS="${AVALANCHE_TRIALS:-128}"
    WALSH_SAMPLES="${WALSH_SAMPLES:-1024}"
    MI_SAMPLES="${MI_SAMPLES:-512}"
    ROTATIONAL_TRIALS="${ROTATIONAL_TRIALS:-128}"
    STATE_TRACE_SAMPLES="${STATE_TRACE_SAMPLES:-24}"
    HO_SAMPLES="${HO_SAMPLES:-16}"
    LATTICE_SAMPLES="${LATTICE_SAMPLES:-2}"
    ;;
  full)
    ROUNDS="${ROUNDS:-1 2 4 8 16 32}"
    DIFF_TRIALS="${DIFF_TRIALS:-64}"
    DIFF_SEARCHES="${DIFF_SEARCHES:-128}"
    AVALANCHE_TRIALS="${AVALANCHE_TRIALS:-10000}"
    WALSH_SAMPLES="${WALSH_SAMPLES:-100000}"
    MI_SAMPLES="${MI_SAMPLES:-20000}"
    ROTATIONAL_TRIALS="${ROTATIONAL_TRIALS:-2000}"
    STATE_TRACE_SAMPLES="${STATE_TRACE_SAMPLES:-256}"
    HO_SAMPLES="${HO_SAMPLES:-128}"
    LATTICE_SAMPLES="${LATTICE_SAMPLES:-16}"
    ;;
  standard)
    ROUNDS="${ROUNDS:-1 2 4 8 16 32}"
    DIFF_TRIALS="${DIFF_TRIALS:-24}"
    DIFF_SEARCHES="${DIFF_SEARCHES:-48}"
    AVALANCHE_TRIALS="${AVALANCHE_TRIALS:-512}"
    WALSH_SAMPLES="${WALSH_SAMPLES:-4096}"
    MI_SAMPLES="${MI_SAMPLES:-2048}"
    ROTATIONAL_TRIALS="${ROTATIONAL_TRIALS:-512}"
    STATE_TRACE_SAMPLES="${STATE_TRACE_SAMPLES:-64}"
    HO_SAMPLES="${HO_SAMPLES:-32}"
    LATTICE_SAMPLES="${LATTICE_SAMPLES:-4}"
    ;;
  *) echo "invalid mode: $MODE" >&2; exit 2 ;;
esac

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="out/attack_suite/$TIMESTAMP"
LOG_DIR="$RUN_DIR/logs"
MANIFEST_DIR="out/manifests"
SUMMARY_DIR="out/summaries"
COMMAND_LOG="$RUN_DIR/commands.log"
MANIFEST="$MANIFEST_DIR/$TIMESTAMP.json"
SUMMARY="$SUMMARY_DIR/latest.md"

mkdir -p "$LOG_DIR" "$MANIFEST_DIR" "$SUMMARY_DIR" "$RUN_DIR"/{walsh,mutual_info,higher_order,state_trace,state_rank,lattice,differential,stat_avalanche,rotational}
: > "$COMMAND_LOG"

FAILURES=0
OPTIONAL_FAILURES=0

join_csv() {
  local out=""
  for item in "$@"; do
    if [[ -z "$out" ]]; then out="$item"; else out="$out,$item"; fi
  done
  printf '%s' "$out"
}

max_round() {
  local max=0
  for item in "$@"; do
    if (( item > max )); then max="$item"; fi
  done
  printf '%s' "$max"
}

copy_if_exists() {
  local src="$1"
  local dst="$2"
  if [[ -f "$src" ]]; then
    mkdir -p "$(dirname "$dst")"
    cp -f "$src" "$dst"
  fi
}

run_cmd() {
  local name="$1"
  shift
  local log="$LOG_DIR/$name.log"
  printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*" >> "$COMMAND_LOG"
  echo "running $name"
  "$@" >"$log" 2>&1
  local status=$?
  printf '[%s] exit=%d %s\n' "$(date -u +%FT%TZ)" "$status" "$name" >> "$COMMAND_LOG"
  if (( status != 0 )); then
    echo "warning: $name failed with exit $status; see $log" >&2
    FAILURES=$((FAILURES + 1))
  fi
  return "$status"
}

run_optional_cmd() {
  local name="$1"
  shift
  local log="$LOG_DIR/$name.log"
  printf '[%s] optional %s\n' "$(date -u +%FT%TZ)" "$*" >> "$COMMAND_LOG"
  echo "running optional $name"
  "$@" >"$log" 2>&1
  local status=$?
  printf '[%s] optional_exit=%d %s\n' "$(date -u +%FT%TZ)" "$status" "$name" >> "$COMMAND_LOG"
  if (( status != 0 )); then
    echo "warning: optional $name failed with exit $status; see $log" >&2
    OPTIONAL_FAILURES=$((OPTIONAL_FAILURES + 1))
  fi
  return 0
}

run_lattice_solver() {
  local eta="$1"
  local lattice_dir="$2"
  local sage_script="$lattice_dir/attack_lll_bkz.sage"
  local python_script="$lattice_dir/attack_lll_bkz.py"

  if [[ "$RUN_LATTICE_SOLVER" == "none" ]]; then
    return 0
  fi

  case "$RUN_LATTICE_SOLVER" in
    auto)
      if [[ -f "$sage_script" ]] && ! grep -q "sage\\.all\\|IntegerLattice" "$sage_script"; then
        run_optional_cmd "lattice_solver_python_sage_eta${eta}" python3 "$sage_script" --out-dir "$lattice_dir"
      elif [[ -f "$sage_script" ]] && command -v sage >/dev/null 2>&1; then
        run_optional_cmd "lattice_solver_sage_python_eta${eta}" sage -python "$sage_script" --out-dir "$lattice_dir"
      elif [[ -f "$python_script" ]]; then
        run_optional_cmd "lattice_solver_python_eta${eta}" python3 "$python_script"
      else
        echo "warning: optional lattice solver skipped for eta=$eta; no generated solver script found" >&2
        OPTIONAL_FAILURES=$((OPTIONAL_FAILURES + 1))
      fi
      ;;
    python)
      if [[ -f "$sage_script" ]] && ! grep -q "sage\\.all\\|IntegerLattice" "$sage_script"; then
        run_optional_cmd "lattice_solver_python_sage_eta${eta}" python3 "$sage_script" --out-dir "$lattice_dir"
      elif [[ -f "$python_script" ]]; then
        run_optional_cmd "lattice_solver_python_eta${eta}" python3 "$python_script"
      else
        echo "warning: optional lattice solver skipped for eta=$eta; Python-compatible solver missing" >&2
        OPTIONAL_FAILURES=$((OPTIONAL_FAILURES + 1))
      fi
      ;;
    sage-python)
      if [[ -f "$sage_script" ]] && command -v sage >/dev/null 2>&1; then
        run_optional_cmd "lattice_solver_sage_python_eta${eta}" sage -python "$sage_script" --out-dir "$lattice_dir"
      else
        echo "warning: optional lattice solver skipped for eta=$eta; sage unavailable or script missing" >&2
        OPTIONAL_FAILURES=$((OPTIONAL_FAILURES + 1))
      fi
      ;;
    *)
      echo "warning: unknown RUN_LATTICE_SOLVER=$RUN_LATTICE_SOLVER; skipping optional lattice solver for eta=$eta" >&2
      OPTIONAL_FAILURES=$((OPTIONAL_FAILURES + 1))
      ;;
  esac
}

IFS=' ' read -r -a ETA_LIST <<< "$ETAS"
IFS=' ' read -r -a ROUND_LIST <<< "$ROUNDS"
ROUNDS_CSV="$(join_csv "${ROUND_LIST[@]}")"
MAX_ROUND="$(max_round "${ROUND_LIST[@]}")"

GO_ATTACK='GOCACHE=/tmp/go-build-cache go run ./cmd/relweattack'

for eta in "${ETA_LIST[@]}"; do
  for round in "${ROUND_LIST[@]}"; do
    run_cmd "differential_eta${eta}_r${round}" bash -lc "cd go && $GO_ATTACK --seed $SEED --eta $eta --threads $THREADS --attacks differential --differential-rounds $round --differential-trials $DIFF_TRIALS --differential-flips 1,2,4,8 --differential-searches $DIFF_SEARCHES --message-len $MESSAGE_LEN"
    run_cmd "stat_avalanche_eta${eta}_r${round}" bash -lc "cd go && $GO_ATTACK --seed $SEED --eta $eta --threads $THREADS --attacks stat-avalanche --stat-avalanche-rounds $round --stat-avalanche-trials $AVALANCHE_TRIALS --message-len $MESSAGE_LEN"
    run_cmd "rotational_eta${eta}_r${round}" bash -lc "cd go && $GO_ATTACK --seed $SEED --eta $eta --threads $THREADS --attacks rotational --rotational-rounds $round --rotational-trials $ROTATIONAL_TRIALS --message-len $MESSAGE_LEN"

    run_cmd "walsh_eta${eta}_r${round}" bash -lc "cd go && $GO_ATTACK --seed $SEED --eta $eta --threads $THREADS --attacks walsh-bias --walsh-rounds $round --walsh-samples $WALSH_SAMPLES --walsh-output-bits 8 --walsh-max-mask-weight 4"
    copy_if_exists "go/out/walsh/walsh_eta${eta}.csv" "$RUN_DIR/walsh/walsh_eta${eta}_r${round}.csv"

    run_cmd "mutual_info_eta${eta}_r${round}" bash -lc "cd go && $GO_ATTACK --seed $SEED --eta $eta --threads $THREADS --attacks mutual-info --mi-rounds $round --mi-samples $MI_SAMPLES --mi-target all"
    copy_if_exists "go/out/mutual_info/mi_eta${eta}.csv" "$RUN_DIR/mutual_info/mutual_info_eta${eta}_r${round}.csv"

    run_cmd "higher_order_eta${eta}_r${round}" bash -lc "cd go && $GO_ATTACK --seed $SEED --eta $eta --threads $THREADS --attacks higher-order-state --ho-order $HO_ORDER --ho-rounds $round --ho-samples $HO_SAMPLES --ho-message-bits $STATE_TRACE_MESSAGE_BITS --ho-target all"
    copy_if_exists "go/out/higher_order/ho_eta${eta}_order${HO_ORDER}.csv" "$RUN_DIR/higher_order/higher_order_eta${eta}_r${round}.csv"
  done

  STATE_TRACE_CSV="$RUN_DIR/state_trace/state_trace_eta${eta}.csv"
  STATE_RANK_CSV="$RUN_DIR/state_rank/state_rank_eta${eta}.csv"
  run_cmd "state_trace_eta${eta}" bash -lc "cd go && $GO_ATTACK --seed $SEED --eta $eta --threads $THREADS --attacks state-trace --state-trace-rounds $MAX_ROUND --state-trace-samples $STATE_TRACE_SAMPLES --state-trace-message-bits $STATE_TRACE_MESSAGE_BITS --state-trace-output ../$STATE_TRACE_CSV"
  run_cmd "state_rank_eta${eta}" bash -lc "cd go && $GO_ATTACK --seed $SEED --eta $eta --threads $THREADS --attacks state-rank --state-rank-input ../$STATE_TRACE_CSV --state-rank-output ../$STATE_RANK_CSV --state-rank-target all --state-rank-max-rows 4096"

  LATTICE_DIR="$RUN_DIR/lattice/eta${eta}"
  run_cmd "lattice_eta${eta}" bash -lc "cd go && $GO_ATTACK --seed $SEED --eta $eta --threads $THREADS --attacks lattice --lattice-rounds 1,2 --lattice-n 16,32 --lattice-eta $eta --lattice-samples $LATTICE_SAMPLES --lattice-output-dir ../$LATTICE_DIR"
  run_lattice_solver "$eta" "$LATTICE_DIR"
done

python3 - "$MANIFEST" "$RUN_DIR" "$COMMAND_LOG" "$MODE" "$ETAS" "$ROUNDS" "$THREADS" "$SEED" "$FAILURES" "$OPTIONAL_FAILURES" \
  "$DIFF_TRIALS" "$DIFF_SEARCHES" "$AVALANCHE_TRIALS" "$WALSH_SAMPLES" "$MI_SAMPLES" \
  "$ROTATIONAL_TRIALS" "$STATE_TRACE_SAMPLES" "$HO_SAMPLES" "$LATTICE_SAMPLES" <<'PY'
import json, os, platform, socket, subprocess, sys, time

manifest_path, run_dir, command_log, mode, etas, rounds, threads, seed, failures, optional_failures = sys.argv[1:11]
sample_keys = [
    "differential_trials", "differential_searches", "avalanche_trials",
    "walsh_samples", "mutual_info_samples", "rotational_trials",
    "state_trace_samples", "higher_order_samples", "lattice_samples",
]
sample_values = sys.argv[11:]

def cmd(args):
    try:
        return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return "unknown"

def first_lscpu(names):
    try:
        out = subprocess.check_output(["lscpu"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            for name in names:
                if line.startswith(name + ":"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "unknown"

makefile = "Makefile"
cflags = "unknown"
ldflags = "unknown"
try:
    with open(makefile, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("CFLAGS"):
                cflags = line.strip()
            if line.startswith("LDFLAGS"):
                ldflags = line.strip()
except OSError:
    pass

data = {
    "schema": "relwe-attack-suite-v1",
    "mode": mode,
    "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "git_commit": cmd(["git", "rev-parse", "HEAD"]),
    "git_dirty": cmd(["git", "status", "--short"]),
    "hostname": socket.gethostname(),
    "cpu": {
        "model": first_lscpu(["Model name", "Processor"]),
        "threads": os.cpu_count(),
    },
    "go_version": cmd(["go", "version"]),
    "compiler_flags": {
        "cflags": cflags,
        "ldflags": ldflags,
    },
    "parameters": {
        "eta": [int(x) for x in etas.split()],
        "rounds": [int(x) for x in rounds.split()],
        "threads": int(threads),
        "seed": int(seed),
        **{k: int(v) for k, v in zip(sample_keys, sample_values)},
    },
    "failures": {
        "command_failures": int(failures),
        "optional_failures": int(optional_failures),
    },
    "paths": {
        "run_dir": run_dir,
        "command_log": command_log,
    },
}
os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
with open(manifest_path, "w", encoding="utf-8") as fh:
    json.dump(data, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(f"manifest: {manifest_path}")
PY
if (( $? != 0 )); then
  echo "warning: manifest generation failed" >&2
  FAILURES=$((FAILURES + 1))
fi

python3 - "$SUMMARY" "$RUN_DIR" "$MANIFEST" "$FAILURES" "$OPTIONAL_FAILURES" <<'PY'
import csv, glob, math, os, re, sys

summary_path, run_dir, manifest_path, failures, optional_failures = sys.argv[1:6]

def rows(path):
    try:
        with open(path, newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))
    except Exception:
        return []

def max_float(paths, col):
    best = None
    best_path = ""
    for path in paths:
        for row in rows(path):
            try:
                val = float(row[col])
            except Exception:
                continue
            if best is None or val > best:
                best = val
                best_path = path
    return best, best_path

def max_int(paths, col):
    best = None
    best_path = ""
    for path in paths:
        for row in rows(path):
            try:
                val = int(float(row[col]))
            except Exception:
                continue
            if best is None or val > best:
                best = val
                best_path = path
    return best, best_path

def parse_avalanche(logs):
    best = []
    for path in logs:
        text = open(path, encoding="utf-8", errors="replace").read()
        mean = re.search(r"mean:\s+([0-9.]+)\s+bits\s+\(([0-9.]+)%\)", text)
        std = re.search(r"stddev:\s+([0-9.]+)", text)
        band = re.search(r"45~55% ratio:\s+([0-9.]+)%", text)
        if mean:
            best.append((path, mean.group(1), mean.group(2), std.group(1) if std else "n/a", band.group(1) if band else "n/a"))
    return best

def parse_rotational(logs):
    mins = []
    warnings = 0
    for path in logs:
        text = open(path, encoding="utf-8", errors="replace").read()
        warnings += text.count("Potential rotational relation")
        for m in re.finditer(r"^\s*(\d+)\s+\|\s+(\d+)\s+\|\s+([0-9.]+)\s+\|\s+(\d+)\s+\|\s+(\d+)\s+\|\s+([0-9.]+)", text, re.M):
            mins.append((float(m.group(3)), path, m.group(1)))
    mins.sort()
    return mins[:5], warnings

def lattice_summary(paths):
    total = success = failure = 0
    notes = []
    for path in paths:
        for row in rows(path):
            total += 1
            status = " ".join(str(v).lower() for v in row.values())
            success_value = str(row.get("success", "")).lower()
            detected_value = str(row.get("hidden_relation_detected", "")).lower()
            if success_value == "true" or detected_value == "true":
                success += 1
            elif success_value == "false" or detected_value == "false" or "not_recovered" in status or "not_detected" in status:
                failure += 1
        if rows(path):
            notes.append(path)
    return total, success, failure, notes

avalanche = parse_avalanche(glob.glob(os.path.join(run_dir, "logs", "stat_avalanche_*.log")))
walsh, walsh_path = max_float(glob.glob(os.path.join(run_dir, "walsh", "*.csv")), "max_abs_bias")
mi, mi_path = max_float(glob.glob(os.path.join(run_dir, "mutual_info", "*.csv")), "max_mutual_information")
rot_min, rot_warnings = parse_rotational(glob.glob(os.path.join(run_dir, "logs", "rotational_*.log")))
rank_def, rank_path = max_int(glob.glob(os.path.join(run_dir, "state_rank", "*.csv")), "deficiency")
ho_zero, ho_zero_path = max_float(glob.glob(os.path.join(run_dir, "higher_order", "*.csv")), "zero_ratio")
ho_dup, ho_dup_path = max_float(glob.glob(os.path.join(run_dir, "higher_order", "*.csv")), "duplicate_ratio")
lat_paths = glob.glob(os.path.join(run_dir, "lattice", "**", "solver_results.csv"), recursive=True)
lat_paths += glob.glob(os.path.join(run_dir, "lattice", "**", "python_summary.csv"), recursive=True)
if not lat_paths:
    lat_paths = glob.glob(os.path.join(run_dir, "lattice", "**", "summary.csv"), recursive=True)
lat_total, lat_success, lat_failure, lat_notes = lattice_summary(lat_paths)

os.makedirs(os.path.dirname(summary_path), exist_ok=True)
with open(summary_path, "w", encoding="utf-8") as fh:
    fh.write("# Re-LWE Attack Suite Summary\n\n")
    fh.write(f"- Run directory: `{run_dir}`\n")
    fh.write(f"- Manifest: `{manifest_path}`\n")
    fh.write(f"- Command failures: {failures}\n")
    fh.write(f"- Optional solver failures/skips: {optional_failures}\n\n")
    fh.write("## Avalanche\n\n")
    if avalanche:
        fh.write("| log | mean bits | mean % | stddev | 45-55% ratio |\n")
        fh.write("| --- | ---: | ---: | ---: | ---: |\n")
        for path, mean, pct, std, band in avalanche[:12]:
            fh.write(f"| `{os.path.basename(path)}` | {mean} | {pct} | {std} | {band} |\n")
    else:
        fh.write("No stat-avalanche logs found.\n")
    fh.write("\n## Bias And Information\n\n")
    fh.write(f"- Walsh max bias: {walsh if walsh is not None else 'n/a'} (`{walsh_path}`)\n")
    fh.write(f"- Mutual information max: {mi if mi is not None else 'n/a'} (`{mi_path}`)\n")
    fh.write("\n## Rotational\n\n")
    fh.write(f"- Potential relation warnings: {rot_warnings}\n")
    if rot_min:
        fh.write("- Lowest mean relation distances:\n")
        for val, path, shift in rot_min:
            fh.write(f"  - {val:.4f} at shift {shift} (`{os.path.basename(path)}`)\n")
    fh.write("\n## State Rank\n\n")
    fh.write(f"- Max rank deficiency: {rank_def if rank_def is not None else 'n/a'} (`{rank_path}`)\n")
    fh.write("\n## Higher-Order State\n\n")
    fh.write(f"- Max zero derivative ratio: {ho_zero if ho_zero is not None else 'n/a'} (`{ho_zero_path}`)\n")
    fh.write(f"- Max duplicate derivative ratio: {ho_dup if ho_dup is not None else 'n/a'} (`{ho_dup_path}`)\n")
    fh.write("\n## Lattice\n\n")
    fh.write(f"- Optional solver failures/skips: {optional_failures}\n")
    fh.write(f"- Result rows: {lat_total}\n")
    fh.write(f"- Cryptanalytic success/detection rows: {lat_success}\n")
    fh.write(f"- Cryptanalytic failure/non-detection rows: {lat_failure}\n")
    for path in lat_notes[:8]:
        fh.write(f"- `{path}`\n")
print(f"summary: {summary_path}")
PY
if (( $? != 0 )); then
  echo "warning: summary generation failed" >&2
  FAILURES=$((FAILURES + 1))
fi

echo "run directory: $RUN_DIR"
echo "manifest: $MANIFEST"
echo "summary: $SUMMARY"

if (( STRICT_OPTIONAL != 0 && OPTIONAL_FAILURES != 0 )); then
  exit 1
fi

if (( FAILURES != 0 )); then
  exit 1
fi
