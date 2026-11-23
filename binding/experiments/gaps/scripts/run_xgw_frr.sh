#!/usr/bin/env bash
# W23 Task 2: cross-gateway FRR. One (cfg, gw, fw) topology. Run from binding/harness.
#   cfg in {bedge,bstrict,borigin,da,db}; gw in {envoy,traefik,kong,apisix,haproxy,nginx}.
# SCEN (env, default "S0-identity,S4") selects which FRR scenarios to send. With no rewrite injection,
# only the non-rewriting scenarios (S0 identity, S4 percent-encoded ids) are meaningful; the rewrite
# scenarios need a per-gateway rewrite (see run_xgw_frr_rw.sh). Reuses the defence topo() helper.
set -uo pipefail
cfg=$1; gw=$2; fw=$3
G=../experiments/gaps; DS=../experiments/defence/scripts; PM=$G/pathmap
PY=orchestrator/.venv/bin/python
id=w23-xgw-$cfg-$gw-$fw; Y=$G/xgw/topos/$id.yaml; out=$G/xgw/runs/$cfg/$id
scen=${SCEN:-S0-identity,S4}
mkdir -p $G/xgw/topos "$out"; rm -rf "$out"; mkdir -p "$out"
port=$(( 29800 + $(echo "$cfg-$gw-$fw" | cksum | cut -d' ' -f1) % 180 ))
$PY - "$cfg" "$gw" "$fw" "$port" "$Y" <<'PYEOF'
import sys, yaml, importlib.util, os
cfg, gw, fw, port, y = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
mt_path = os.path.join("..", "experiments", "defence", "scripts", "make_topologies.py")
spec = importlib.util.spec_from_file_location("mt", mt_path); mt = importlib.util.module_from_spec(spec); spec.loader.exec_module(mt)
t = mt.topo(os.path.basename(y)[:-5], gw, fw, "off", cfg, port)
assert t is not None, (cfg, gw, fw)
yaml.safe_dump(t, open(y, "w"), sort_keys=False)
PYEOF
export BH_PROJECT_PREFIX=w23-bh-; proj=w23-bh-$id
if ! $PY -m orchestrator.up $Y --stubs off --fresh-logs --timeout 300 > "$out/up.log" 2>&1; then
  echo "UP FAILED $cfg $gw $fw" | tee "$out/status.txt"; $PY -m orchestrator.down $Y >/dev/null 2>&1; rm -rf orchestrator/generated/$id; exit 1; fi
sleep 2
$PY $PM/scripts/frr_client.py --port $port --scenario "$scen" --out "$out/frr.jsonl" > "$out/client.log" 2>&1
docker compose -p $proj logs --no-color --tail 300 gateway > "$out/gateway.log" 2>&1 || true
$PY -m orchestrator.down $Y > "$out/down.log" 2>&1
cp logs/$id/*.jsonl "$out/" 2>/dev/null || true
mkdir -p "$out/generated" && cp -R orchestrator/generated/$id/. "$out/generated/" 2>/dev/null; rm -rf orchestrator/generated/$id
n=$(wc -l < "$out/frr.jsonl" 2>/dev/null|tr -d ' '); okc=$(python3 -c "import json;print(sum(json.loads(l)['ok'] for l in open('$out/frr.jsonl')))" 2>/dev/null||echo 0)
echo "$cfg $gw $fw ok=$okc/$n" | tee "$out/status.txt"
