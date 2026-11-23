#!/usr/bin/env bash
# One A5 G2 strict/control topology. Run from binding/harness. Usage: run_g2.sh <id> [outroot]
set -uo pipefail
id=$1
K=$(cd ../experiments/ablation && pwd); ROOT=${2:-$K/strict/runs}
PY=orchestrator/.venv/bin/python
Y=$K/strict/topologies/$id.yaml
fw=$(grep '^framework:' $Y | awk '{print $2}')
out=$ROOT/$id; rm -rf "$out"; mkdir -p "$out"
export BH_PROJECT_PREFIX=w18-bh-; P=w18-bh-$id; t0=$(date +%s)
if ! $PY -m orchestrator.up $Y --stubs off --fresh-logs --timeout 300 > "$out/up.log" 2>&1; then
  echo "UP FAILED $id" | tee -a "$out/status.txt"; $PY -m orchestrator.down $Y >> "$out/down.log" 2>&1; exit 1; fi
docker compose -p $P images --format json > "$out/images.json" 2>/dev/null || true
$PY $K/scripts/ab_run_matrix.py --topology $Y --cases ${CASES:-$K/strict/cases_g2.jsonl} --bind full --out logs/$id/runner.jsonl > "$out/runner.stderr.log" 2>&1; rc=$?
sleep 1
docker compose -p $P logs --no-color --tail 300 gateway > "$out/gateway.log" 2>&1 || true
$PY -m orchestrator.down $Y > "$out/down.log" 2>&1
cp logs/$id/*.jsonl "$out/"
mkdir -p "$out/generated" && cp -R orchestrator/generated/$id/. "$out/generated/" && rm -rf orchestrator/generated/$id
$PY -m oracle.correlate --log-dir "$out" --topology $Y --ground-truth $K/groundtruth/$fw-ovoff.jsonl \
    --summary-csv $ROOT/summary.csv > "$out/correlate.log" 2>&1
echo "$id rc=$rc secs=$(( $(date +%s)-t0 )) $(tail -1 $out/correlate.log | cut -c1-200)" | tee "$out/status.txt"
