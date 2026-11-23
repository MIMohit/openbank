#!/usr/bin/env bash
# Like run_one.sh, but brings the topology up with the executor's baked-in Docker
# HEALTHCHECK disabled via a compose override. Needed ONLY for bh-exec-laravel:latest,
# whose image healthcheck probes Caddy's :2019/metrics and reports unhealthy even though
# the app serves /api/v1/health = 200 (a W5 image bug, outside W12 ownership). The probe
# sidecar still gates gateway readiness, so this does not weaken the measurement.
# Usage (from binding/harness): run_one_hcfix.sh <topology-id> [outdir-root] [cases-file]
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

# 1. generate compose (no bring-up), then write a healthcheck-disable override.
gen=$($PY - "$Y" <<'PYEOF'
import sys
sys.path.insert(0, ".")
from orchestrator.compose import generate, project_name
from orchestrator.topology import load
t = load(sys.argv[1])
path, meta = generate(t, "off")
print(path)
PYEOF
)
if [ -z "$gen" ] || [ ! -f "$gen" ]; then
  echo "GEN FAILED $id" | tee -a "$out/status.txt"; exit 1
fi
gdir=$(dirname "$gen")
cat > "$gdir/hcfix.override.yml" <<'YML'
services:
  executor:
    healthcheck:
      disable: true
YML

# fresh logs (mirror orchestrator.up --fresh-logs)
rm -f logs/$id/*.jsonl 2>/dev/null || true

if ! docker compose -p "$proj" -f "$gen" -f "$gdir/hcfix.override.yml" up -d --wait --wait-timeout 300 > "$out/up.log" 2>&1; then
  echo "UP FAILED $id" | tee -a "$out/status.txt"
  docker compose -p "$proj" -f "$gen" -f "$gdir/hcfix.override.yml" ps -a >> "$out/up.log" 2>&1
  docker compose -p "$proj" -f "$gen" down -v >> "$out/down.log" 2>&1
  exit 1
fi
# readiness: host port + gateway->executor health 200
port=$(grep -E '^host_port:' "$Y" | awk '{print $2}')
for i in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: api.bench.test' "http://127.0.0.1:$port/api/v1/health" 2>/dev/null || echo 000)
  [ "$code" = "200" ] && break
  sleep 1
done
echo "readiness health=$code port=$port" >> "$out/up.log"

docker compose -p "$proj" -f "$gen" images --format json > "$out/images.json" 2>/dev/null || true
$PY ../experiments/e4/scripts/e4_runner.py --topology "$Y" --cases "$CASES" > "$out/runner.stderr.log" 2>&1
rc=$?
docker compose -p "$proj" -f "$gen" logs --no-color --tail 400 gateway > "$out/gateway.log" 2>&1 || true
docker compose -p "$proj" -f "$gen" down -v > "$out/down.log" 2>&1
cp logs/$id/*.jsonl "$out/" 2>/dev/null || true
mkdir -p "$out/generated" && cp -R "$gdir/." "$out/generated/" 2>/dev/null && rm -rf "$gdir"
$PY ../experiments/e4/scripts/e4_oracle.py --log-dir "$out" --topology "$Y" \
    --summary-csv "$ROOT/summary.csv" > "$out/oracle.log" 2>&1
viol=$(wc -l < "$out/violations.jsonl" 2>/dev/null | tr -d ' ')
echo "$id runner_rc=$rc secs=$(( $(date +%s)-t0 )) violations=${viol:-0} $(tail -1 "$out/runner.stderr.log")" | tee "$out/status.txt"
