#!/usr/bin/env bash
# FRR run (task item 6). From binding/harness: run_frr.sh <cfg> <fw>
# up (orchestrator.up --stubs off) -> inject rewrite scenarios into the GENERATED nginx.conf + reload
# -> legit request set -> down -> copy logs.
set -uo pipefail
cfg=$1; fw=$2
D=$(cd ../experiments/defence && pwd); PY=orchestrator/.venv/bin/python
id=w17-frr-$cfg-$fw; Y=$D/topologies/frr/$id.yaml; out=$D/runs/frr/$cfg/$id
mkdir -p $D/topologies/frr; rm -rf "$out"; mkdir -p "$out"
$PY - "$cfg" "$fw" "$Y" <<'PYEOF'
import sys, yaml, importlib.util, os
cfg, fw, y = sys.argv[1:4]
spec = importlib.util.spec_from_file_location("mt", os.path.join(os.path.dirname(y), "..", "..", "scripts", "make_topologies.py"))
mt = importlib.util.module_from_spec(spec); spec.loader.exec_module(mt)
cfgs = ["bedge", "borigin", "bstrict", "da", "db", "dc"]; fws = ["fastapi", "express", "spring", "aspnet"]
t = mt.topo(os.path.basename(y)[:-5], "nginx", fw, "off", cfg, 29100 + cfgs.index(cfg) * 10 + fws.index(fw))
yaml.safe_dump(t, open(y, "w"), sort_keys=False)
PYEOF
export BH_PROJECT_PREFIX=w17-bh-; proj=w17-bh-$id
if ! $PY -m orchestrator.up $Y --stubs off --fresh-logs --timeout 300 > "$out/up.log" 2>&1; then
  echo "UP FAILED $id" | tee "$out/status.txt"; $PY -m orchestrator.down $Y >/dev/null 2>&1; rm -rf orchestrator/generated/$id; exit 1; fi
port=$(grep host_port $Y | awk '{print $2}')
python3 $D/scripts/frr_nginx.py orchestrator/generated/$id/gateway/nginx.conf
docker exec $proj-gateway-1 nginx -t > "$out/nginx_t.log" 2>&1 && docker exec $proj-gateway-1 nginx -s reload >> "$out/nginx_t.log" 2>&1
sleep 2
$PY $D/scripts/frr_client.py --port $port --out "$out/frr.jsonl" > "$out/client.log" 2>&1
docker compose -p $proj logs --no-color --tail 400 gateway > "$out/gateway.log" 2>&1 || true
$PY -m orchestrator.down $Y > "$out/down.log" 2>&1
cp logs/$id/*.jsonl "$out/" 2>/dev/null || true
mkdir -p "$out/generated" && cp -R orchestrator/generated/$id/. "$out/generated/" 2>/dev/null; rm -rf orchestrator/generated/$id
echo "$cfg $fw $(python3 -c "import json;r=[json.loads(l) for l in open('$out/frr.jsonl')];print(sum(x['ok'] for x in r),'/',len(r),'ok')")" | tee "$out/status.txt"
