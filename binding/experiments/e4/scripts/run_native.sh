#!/usr/bin/env bash
# E4 native-ACL runner: real bh-verifier (DPoP proof only) + a gateway that authorizes with
# its OWN native path ACL (config swapped in from experiments/e4/native/configs). Measures
# whether the same A_client battery bypasses a native ACL. Reuses e4_oracle unchanged: a
# violation = proof accepted (verifier allow) AND executor executed a forbidden op, i.e. the
# native ACL was bypassed.
# Usage (from binding/harness): run_native.sh <topology-id> <config-src>
set -uo pipefail
id=$1; cfgsrc=$2
E4=$(cd ../experiments/e4 && pwd)
PY=orchestrator/.venv/bin/python
Y=$E4/native/topologies/$id.yaml
ROOT=$E4/native/runs; out=$ROOT/$id; rm -rf "$out"; mkdir -p "$out"
export BH_PROJECT_PREFIX=w12-bh-
proj=w12-bh-$id
t0=$(date +%s)
gen=$($PY - "$Y" <<'PYEOF'
import sys; sys.path.insert(0,".")
from orchestrator.compose import generate
from orchestrator.topology import load
path,meta=generate(load(sys.argv[1]),"off"); print(path)
PYEOF
)
gdir=$(dirname "$gen")
# swap in the native-ACL gateway config (overwrite the rendered one)
dst=$(ls "$gdir/gateway/" | grep -E '\.(conf|yaml|yml)$' | grep -vE 'dynamic|traefik\.yml' | head -1)
cp "$E4/native/configs/$cfgsrc" "$gdir/gateway/$dst"
echo "swapped $cfgsrc -> gateway/$dst" > "$out/native.log"
rm -f logs/$id/*.jsonl 2>/dev/null || true
if ! docker compose -p "$proj" -f "$gen" up -d --wait --wait-timeout 300 > "$out/up.log" 2>&1; then
  echo "UP FAILED $id" | tee -a "$out/status.txt"
  docker compose -p "$proj" -f "$gen" ps -a >> "$out/up.log" 2>&1
  docker compose -p "$proj" -f "$gen" logs --tail 40 gateway >> "$out/up.log" 2>&1
  docker compose -p "$proj" -f "$gen" down -v >> "$out/down.log" 2>&1
  exit 1
fi
port=$(grep -E '^host_port:' "$Y" | awk '{print $2}')
$PY ../experiments/e4/scripts/e4_runner.py --topology "$Y" --cases "$E4/cases.jsonl" > "$out/runner.stderr.log" 2>&1
rc=$?
docker compose -p "$proj" -f "$gen" logs --no-color --tail 400 gateway > "$out/gateway.log" 2>&1 || true
docker compose -p "$proj" -f "$gen" down -v > "$out/down.log" 2>&1
cp logs/$id/*.jsonl "$out/" 2>/dev/null || true
mkdir -p "$out/generated" && cp -R "$gdir/." "$out/generated/" 2>/dev/null && rm -rf "$gdir"
$PY ../experiments/e4/scripts/e4_oracle.py --log-dir "$out" --topology "$Y" \
    --summary-csv "$ROOT/summary.csv" > "$out/oracle.log" 2>&1
viol=$(wc -l < "$out/violations.jsonl" 2>/dev/null | tr -d ' ')
echo "$id runner_rc=$rc secs=$(( $(date +%s)-t0 )) violations=${viol:-0} $(tail -1 "$out/runner.stderr.log")" | tee "$out/status.txt"
