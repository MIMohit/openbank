#!/usr/bin/env bash
# One E7/E8 run: up (real images, --stubs off) -> replay case set -> down -> copy logs -> oracle.
# Adapted copy of experiments/{kill,ext-routes,e4}/scripts/run_one.sh. Run from binding/harness.
# Usage: run_one.sh <kind aleak|e4> <cfg> <source> <topology-id>
set -uo pipefail
kind=$1; cfg=$2; src=$3; id=$4
D=$(cd ../experiments/defence && pwd); S=$D/scripts
PY=orchestrator/.venv/bin/python
Y=$D/topologies/${TOPO_DIR:-$cfg}/$id.yaml
fw=$(grep '^framework:' $Y | awk '{print $2}'); ov=$(grep '^override:' $Y | tr -d "'" | awk '{print $2}')
out=$D/${OUT_ROOT:-runs}/${TOPO_DIR:-$cfg}/$id; rm -rf "$out"; mkdir -p "$out"
export BH_PROJECT_PREFIX=w17-bh-
proj=w17-bh-$id
t0=$(date +%s)
if ! $PY -m orchestrator.up $Y --stubs off --fresh-logs --timeout 300 > "$out/up.log" 2>&1; then
  echo "UP FAILED $id" | tee -a "$out/status.txt"
  docker compose -p $proj logs --no-color --tail 100 > "$out/up_fail_logs.txt" 2>&1 || true
  $PY -m orchestrator.down $Y >> "$out/down.log" 2>&1
  rm -rf orchestrator/generated/$id
  exit 1
fi
docker compose -p $proj images --format json > "$out/images.json" 2>/dev/null || true
if [ "$kind" = e4 ]; then
  $PY ../experiments/e4/scripts/e4_runner.py --topology "$Y" --cases ../experiments/e4/cases.jsonl > "$out/runner.stderr.log" 2>&1
else
  $PY $S/ext_run_matrix.py --topology $Y --cases ${CASES:-$D/cases/$src.jsonl} --out logs/$id/runner.jsonl > "$out/runner.stderr.log" 2>&1
fi
rc=$?
docker compose -p $proj logs --no-color --tail 400 gateway > "$out/gateway.log" 2>&1 || true
$PY -m orchestrator.down $Y > "$out/down.log" 2>&1
cp logs/$id/*.jsonl "$out/" 2>/dev/null || true
mkdir -p "$out/generated" && cp -R orchestrator/generated/$id/. "$out/generated/" 2>/dev/null; rm -rf orchestrator/generated/$id
if [ "$kind" = e4 ]; then
  $PY ../experiments/e4/scripts/e4_oracle.py --log-dir "$out" --topology "$Y" > "$out/oracle.log" 2>&1
  n=$(wc -l < "$out/violations.jsonl" 2>/dev/null | tr -d ' ')
else
  $PY -m oracle.correlate --log-dir "$out" --topology $Y --ground-truth $D/groundtruth/$fw-ov$ov.jsonl > "$out/correlate.log" 2>&1
  n=$(wc -l < "$out/hits.jsonl" 2>/dev/null | tr -d ' ')
fi
echo "$cfg $src $id runner_rc=$rc secs=$(( $(date +%s)-t0 )) hits=${n:-NA} $(tail -1 $out/runner.stderr.log)" | tee "$out/status.txt"
