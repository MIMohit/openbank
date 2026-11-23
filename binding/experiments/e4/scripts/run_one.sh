#!/usr/bin/env bash
# One E4 topology: up (real PDP+gateway+executor, --stubs off) -> A_client battery ->
# down -> copy logs -> e4 authorization oracle.
# Usage (run from binding/harness):  run_one.sh <topology-id> [outdir-root] [cases-file]
set -uo pipefail
id=$1
E4=$(cd ../experiments/e4 && pwd)
ROOT=${2:-$E4/runs}
CASES=${3:-$E4/cases.jsonl}
PY=orchestrator/.venv/bin/python
Y=$E4/topologies/$id.yaml
out=$ROOT/$id; rm -rf "$out"; mkdir -p "$out"
export BH_PROJECT_PREFIX=w12-bh-
proj=w12-bh-$id
t0=$(date +%s)
if ! $PY -m orchestrator.up "$Y" --stubs off --fresh-logs --timeout 300 > "$out/up.log" 2>&1; then
  echo "UP FAILED $id" | tee -a "$out/status.txt"
  $PY -m orchestrator.down "$Y" >> "$out/down.log" 2>&1
  exit 1
fi
docker compose -p "$proj" images --format json > "$out/images.json" 2>/dev/null || true
$PY ../experiments/e4/scripts/e4_runner.py --topology "$Y" --cases "$CASES" > "$out/runner.stderr.log" 2>&1
rc=$?
docker compose -p "$proj" logs --no-color --tail 400 gateway > "$out/gateway.log" 2>&1 || true
$PY -m orchestrator.down "$Y" > "$out/down.log" 2>&1
cp logs/$id/*.jsonl "$out/" 2>/dev/null || true
mkdir -p "$out/generated" && cp -R orchestrator/generated/$id/. "$out/generated/" 2>/dev/null && rm -rf orchestrator/generated/$id
$PY ../experiments/e4/scripts/e4_oracle.py --log-dir "$out" --topology "$Y" \
    --summary-csv "$ROOT/summary.csv" > "$out/oracle.log" 2>&1
viol=$(wc -l < "$out/violations.jsonl" 2>/dev/null | tr -d ' ')
echo "$id runner_rc=$rc secs=$(( $(date +%s)-t0 )) violations=${viol:-0} $(tail -1 "$out/runner.stderr.log")" | tee "$out/status.txt"
