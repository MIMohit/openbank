#!/usr/bin/env bash
# Failure diagnostic for perf (status-code breakdown). Copy of run_perf.sh. Usage: diag_perf.sh <cfg> <fw> "<lvl ...>" [dur]
# One topology up at a time; containers CPU-pinned with `docker update --cpuset-cpus`
# (gateway 0-1, verifier 2-3, executor 4-5, k6 6-9 of the 10-CPU Docker Desktop VM).
set -uo pipefail
cfg=$1; fw=$2; LVLS=$3; DUR=${4:-20s}; MAXDUR=${MAXDUR:-30s}
D=$(cd ../experiments/defence && pwd); PY=orchestrator/.venv/bin/python; SPY=$D/build/.venv-stats/bin/python
id=w17-perf-$cfg-$fw; Y=$D/topologies/perf/$id.yaml; out=$D/results/perf/diag/$cfg-$fw
mkdir -p "$out" $D/topologies/perf
$PY - "$cfg" "$fw" "$Y" <<'PYEOF'
import sys, yaml, importlib.util, os
cfg, fw, y = sys.argv[1:4]
spec = importlib.util.spec_from_file_location("mt", os.path.join(os.path.dirname(y), "..", "..", "scripts", "make_topologies.py"))
mt = importlib.util.module_from_spec(spec); spec.loader.exec_module(mt)
port = 29000 + ["bedge", "borigin", "da", "db"].index(cfg) * 10 + ["fastapi", "spring"].index(fw)
t = mt.topo(os.path.basename(y)[:-5], "nginx", fw, "off", cfg, port)
t["verifier"].update({"jti_cache": "off", "iat_window": 86400})
yaml.safe_dump(t, open(y, "w"), sort_keys=False)
PYEOF
export BH_PROJECT_PREFIX=w17-bh-; proj=w17-bh-$id
$PY -m orchestrator.up $Y --stubs off --fresh-logs --timeout 300 > "$out/up.log" 2>&1 || { echo "UP FAILED $id"; $PY -m orchestrator.down $Y >/dev/null 2>&1; exit 1; }
port=$(grep host_port $Y | awk '{print $2}')
for s in gateway:0,1 verifier:2,3 executor:4,5; do docker update --cpuset-cpus ${s#*:} $proj-${s%%:*}-1 >/dev/null; done
docker compose -p $proj images --format json > "$out/images.json"
read AUTHZ PROOF < <($PY -c "
import sys; sys.path.insert(0,'.')
from runner.minter_adapter import get_minter
a,p,j=get_minter(prefer='w3').mint(client='alice',htm='GET',htu='http://api.bench.test/api/v1/accounts/acc-alice-1'); print(a.replace(' ','~'),p)")
AUTHZ=${AUTHZ//\~/ }
code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: api.bench.test' -H "Authorization: $AUTHZ" -H "DPoP: $PROOF" http://127.0.0.1:$port/api/v1/accounts/acc-alice-1)
echo "sanity status=$code" | tee "$out/sanity.txt"
k6() { docker run --rm --name w17-k6 --network ${proj}_default --cpuset-cpus 6-9 -m 1g \
  -v $D/perf:/scripts:ro -v $out:/out -e TARGET=gateway:8000 -e AUTHZ="$AUTHZ" -e PROOF="$PROOF" "$@"; }
k6 -e MODE=rate -e RATE=200 -e DUR=20s grafana/k6:1.3.0 run -q /scripts/load.js > "$out/warmup.log" 2>&1
for lvl in $LVLS; do
  if [ $lvl = max ]; then m="-e MODE=max -e DUR=$DUR"; else m="-e MODE=rate -e RATE=$lvl -e DUR=$DUR"; fi
  k6 $m grafana/k6:1.3.0 run -q --out csv=/out/$lvl.csv --summary-export /out/$lvl.summary.json /scripts/load.js > "$out/$lvl.log" 2>&1
  python3 - "$out/$lvl.csv" > "$out/$lvl.status.json" <<'PY'
import csv, collections, json, sys
c = collections.Counter(r["status"] for r in csv.DictReader(open(sys.argv[1])) if r["metric_name"] == "http_reqs")
print(json.dumps(dict(c)))
PY
  rm -f "$out/$lvl.csv"; echo "$cfg-$fw $lvl $(cat $out/$lvl.status.json)"
done
docker compose -p $proj logs --no-color --tail 50 > "$out/compose_tail.log" 2>&1
$PY -m orchestrator.down $Y > "$out/down.log" 2>&1; rm -rf orchestrator/generated/$id
echo "diag done $id $(date)"
