#!/usr/bin/env bash
# One ext-routes topology: up (real :v2 images) -> depth-1 runner (ext cases) -> down -> correlate.
# Usage (from binding/harness): run_one.sh <topology-id> [outdir-root]
set -uo pipefail
id=$1
K=$(cd ../experiments/ext-routes && pwd); ROOT=${2:-$K/runs}
S=$K/scripts
PY=orchestrator/.venv/bin/python
Y=$K/topologies/$id.yaml
fw=$(grep '^framework:' $Y | awk '{print $2}'); ov=$(grep '^override:' $Y | tr -d "'" | awk '{print $2}')
out=$ROOT/$id; rm -rf "$out"; mkdir -p "$out"
export BH_PROJECT_PREFIX=w15r-bh-
t0=$(date +%s)
if ! $PY -m orchestrator.up $Y --stubs off --fresh-logs --timeout 300 > "$out/up.log" 2>&1; then
  echo "UP FAILED $id" | tee -a "$out/status.txt"
  $PY -m orchestrator.down $Y >> "$out/down.log" 2>&1
  exit 1
fi
docker compose -p w15r-bh-$id images --format json > "$out/images.json" 2>/dev/null || true
$PY $S/ext_run_matrix.py --topology $Y --cases $K/cases.jsonl --out logs/$id/runner.jsonl > "$out/runner.stderr.log" 2>&1
rc=$?
docker compose -p w15r-bh-$id logs --no-color --tail 400 gateway > "$out/gateway.log" 2>&1 || true
$PY -m orchestrator.down $Y > "$out/down.log" 2>&1
cp logs/$id/*.jsonl "$out/"
mkdir -p "$out/generated" && cp -R orchestrator/generated/$id/. "$out/generated/" && rm -rf orchestrator/generated/$id
$PY -m oracle.correlate --log-dir "$out" --topology $Y --ground-truth $K/groundtruth/$fw-ov$ov.jsonl \
    --summary-csv $ROOT/summary.csv > "$out/correlate.log" 2>&1
echo "$id runner_rc=$rc secs=$(( $(date +%s)-t0 )) $(tail -1 $out/runner.stderr.log)" | tee "$out/status.txt"
