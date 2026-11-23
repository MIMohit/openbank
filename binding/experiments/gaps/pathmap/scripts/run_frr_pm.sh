#!/usr/bin/env bash
# W23 path-map FRR: one (cfg, fw, scenario) topology. Run from binding/harness.
#   up --stubs off -> inject the FRR rewrite scenarios (frr_nginx.py, reused verbatim) ->
#   push the scenario's public->internal map into the executor (docker cp /pathmap.json, read per request)
#   -> send ONLY this scenario's legit requests -> down -> copy logs.
# Isolating traffic to one scenario keeps the internal->public reverse map unambiguous.
# Usage: run_frr_pm.sh <cfg:dapm|dbpm|da|db> <fw> <scenario-prefix> <mapfile>
set -uo pipefail
cfg=$1; fw=$2; scen=$3; mapfile=$4
G=../experiments/gaps/pathmap; DS=../experiments/defence/scripts
PY=orchestrator/.venv/bin/python
id=w23-frrpm-$cfg-$fw-$scen
port=$(( 29400 + $(echo "$cfg-$fw-$scen" | cksum | cut -d' ' -f1) % 150 ))
Y=$G/topos/$id.yaml; out=$G/runs/frr/$cfg/$id
mkdir -p $G/topos "$out"; rm -rf "$out"; mkdir -p "$out"
python3 $G/scripts/make_pm_topo.py "$cfg" "$fw" "$id" "$port" > "$Y"
export BH_PROJECT_PREFIX=w23-bh-; proj=w23-bh-$id
if ! $PY -m orchestrator.up $Y --stubs off --fresh-logs --timeout 300 > "$out/up.log" 2>&1; then
  echo "UP FAILED $id" | tee "$out/status.txt"; $PY -m orchestrator.down $Y >/dev/null 2>&1; rm -rf orchestrator/generated/$id; exit 1; fi
python3 $DS/frr_nginx.py orchestrator/generated/$id/gateway/nginx.conf
docker exec $proj-gateway-1 nginx -t > "$out/nginx_t.log" 2>&1 && docker exec $proj-gateway-1 nginx -s reload >> "$out/nginx_t.log" 2>&1
# push the scenario map into the executor (read per request by the :pathmap image)
exec_ctr=$(docker ps --format '{{.Names}}' | grep "^$proj-executor" | head -1)
docker cp "$mapfile" "$exec_ctr":/pathmap.json && echo "map pushed: $(cat $mapfile)" > "$out/map.log"
sleep 2
$PY $G/scripts/frr_client.py --port $port --scenario "$scen" --out "$out/frr.jsonl" > "$out/client.log" 2>&1
docker compose -p $proj logs --no-color --tail 400 gateway > "$out/gateway.log" 2>&1 || true
$PY -m orchestrator.down $Y > "$out/down.log" 2>&1
cp logs/$id/*.jsonl "$out/" 2>/dev/null || true
mkdir -p "$out/generated" && cp -R orchestrator/generated/$id/. "$out/generated/" 2>/dev/null; rm -rf orchestrator/generated/$id
n=$(wc -l < "$out/frr.jsonl" 2>/dev/null | tr -d ' '); okc=$(python3 -c "import json;print(sum(json.loads(l)['ok'] for l in open('$out/frr.jsonl')))" 2>/dev/null || echo 0)
echo "$cfg $fw $scen ok=$okc/$n" | tee "$out/status.txt"
