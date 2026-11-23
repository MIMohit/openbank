#!/usr/bin/env bash
# Bring up ONE topology (with the digest gate for digest/query-digest), ddmin the given hit cases, tear down.
# Run from binding/harness. Usage: ddmin_run.sh <topology.yaml> <runs-dir> <cases.jsonl> <bind> <gate 0|1> <case-id>...
set -uo pipefail
Y=$1; RUNS=$2; C=$3; bind=$4; gate=$5; shift 5
K=$(cd ../experiments/ablation && pwd); PY=orchestrator/.venv/bin/python
id=$(basename $Y .yaml); export BH_PROJECT_PREFIX=w18-bh-; P=w18-bh-$id
mkdir -p $K/ddmin
$PY -m orchestrator.up $Y --stubs off --fresh-logs --timeout 300 > $K/ddmin/$id.up.log 2>&1 || { $PY -m orchestrator.down $Y >/dev/null 2>&1; echo "UP FAILED $id"; exit 1; }
if [ $gate = 1 ]; then
  conf=orchestrator/generated/$id/gateway/nginx.conf
  net=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' $P-gateway-1 | awk '{print $1}')
  docker run -d --name w18-dg-$id --network $net --network-alias digestgate -m 128m -v "$(pwd)/logs/$id":/logs \
     -e LOG_PATH=/logs/digest_gate.jsonl bh-verifier:ablate python -m verifier.digest_gate > /dev/null
  new=$(sed 's#proxy_pass http://executor:8080;#proxy_pass http://digestgate:8081;#' $conf); printf '%s\n' "$new" > $conf
  sleep 2; docker exec $P-gateway-1 nginx -s reload; sleep 2
fi
$PY $K/scripts/ddmin_hit.py $Y $RUNS $C $bind "$@" 2>&1 | tee -a $K/ddmin/ddmin.log
docker rm -f w18-dg-$id >/dev/null 2>&1
$PY -m orchestrator.down $Y > /dev/null 2>&1; rm -rf orchestrator/generated/$id
