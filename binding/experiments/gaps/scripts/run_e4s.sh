#!/usr/bin/env bash
# One A5 E4 strict topology (copied from e4/scripts/run_one.sh; w18 prefix, own outdir). Run from binding/harness.
set -uo pipefail
id=$1
K=$(cd ../experiments/gaps && pwd); ROOT=${2:-$K/strict/runs_e4}; CASES=${3:-$K/e4_cases.jsonl}
PY=orchestrator/.venv/bin/python
Y=$K/strict/topologies/$id.yaml
out=$ROOT/$id; rm -rf "$out"; mkdir -p "$out"
export BH_PROJECT_PREFIX=w23-bh-; proj=w23-bh-$id; t0=$(date +%s)
if ! $PY -m orchestrator.up "$Y" --stubs off --fresh-logs --timeout 300 > "$out/up.log" 2>&1; then
  echo "UP FAILED $id" | tee -a "$out/status.txt"; $PY -m orchestrator.down "$Y" >> "$out/down.log" 2>&1; exit 1; fi
docker compose -p "$proj" images --format json > "$out/images.json" 2>/dev/null || true
$PY $K/scripts/e4_runner.py --topology "$Y" --cases "$CASES" > "$out/runner.stderr.log" 2>&1; rc=$?
docker compose -p "$proj" logs --no-color --tail 300 gateway > "$out/gateway.log" 2>&1 || true
$PY -m orchestrator.down "$Y" > "$out/down.log" 2>&1
cp logs/$id/*.jsonl "$out/" 2>/dev/null || true
mkdir -p "$out/generated" && cp -R orchestrator/generated/$id/. "$out/generated/" 2>/dev/null && rm -rf orchestrator/generated/$id
$PY $K/scripts/e4_oracle.py --log-dir "$out" --topology "$Y" --summary-csv "$ROOT/summary.csv" > "$out/oracle.log" 2>&1
viol=$(wc -l < "$out/violations.jsonl" 2>/dev/null | tr -d ' ')
echo "$id rc=$rc secs=$(( $(date +%s)-t0 )) violations=${viol:-0} $(tail -1 "$out/runner.stderr.log")" | tee "$out/status.txt"
