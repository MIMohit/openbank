#!/usr/bin/env bash
# One legit-FR topology. Run from binding/harness. haprec: adds the documented HAProxy
# `http-request normalize-uri query-sort-by-name` to the recommended profile (which already applies
# percent-decode-unreserved + percent-to-uppercase before the authz action). digest variants: digest gate hop.
set -uo pipefail
id=$1
K=$(cd ../experiments/ablation && pwd); out=$K/legit/runs/$id; rm -rf "$out"; mkdir -p "$out"
PY=orchestrator/.venv/bin/python; Y=$K/legit/topologies/$id.yaml
v=$(echo $id | sed -E 's/^w18-legit-[a-z]+-//'); g=$(echo $id | sed -E 's/^w18-legit-([a-z]+)-.*/\1/')
case $v in query-exact|query-sorted|query) bind=query;; digest) bind=digest;; query-digest) bind=query-digest;; *) bind=full;; esac
export BH_PROJECT_PREFIX=w18-bh-; P=w18-bh-$id
if ! $PY -m orchestrator.up $Y --stubs off --fresh-logs --timeout 300 > "$out/up.log" 2>&1; then
  echo "UP FAILED $id"; $PY -m orchestrator.down $Y >> "$out/down.log" 2>&1; exit 1; fi
gd=orchestrator/generated/$id/gateway
restart=0
if [ $g = haprec ]; then
  new=$(perl -pe 's/^(    http-request normalize-uri percent-to-uppercase)$/$1\n    http-request normalize-uri query-sort-by-name/' $gd/haproxy.cfg); printf '%s\n' "$new" > $gd/haproxy.cfg; restart=1
fi
case $v in digest|query-digest)
  net=$(docker inspect -f '{{range $k,$x := .NetworkSettings.Networks}}{{$k}} {{end}}' $P-gateway-1 | awk '{print $1}')
  docker run -d --name w18-dg-$id --network $net --network-alias digestgate -m 128m -v "$(pwd)/logs/$id":/logs \
     -e LOG_PATH=/logs/digest_gate.jsonl bh-verifier:ablate python -m verifier.digest_gate > /dev/null
  if [ $g = haprec ]; then new=$(sed 's#server exec executor:8080#server exec digestgate:8081#' $gd/haproxy.cfg); printf '%s\n' "$new" > $gd/haproxy.cfg
  else new=$(sed 's#proxy_pass http://executor:8080;#proxy_pass http://digestgate:8081;#' $gd/nginx.conf); printf '%s\n' "$new" > $gd/nginx.conf; sleep 2; docker exec $P-gateway-1 nginx -s reload; fi ;;
esac
if [ $restart = 1 ]; then docker restart $P-gateway-1 > /dev/null; fi
sleep 3
for i in $(seq 1 30); do curl -s -o /dev/null --max-time 2 http://127.0.0.1:29884/api/v1/health && break; sleep 1; done
cp -R $gd "$out/gateway_conf"
$PY $K/scripts/legit.py --port 29884 --bind $bind --label $id --out "$out/legit.jsonl" 2>&1 | tee "$out/status.txt"
docker logs w18-dg-$id > "$out/gate.log" 2>&1; docker rm -f w18-dg-$id > /dev/null 2>&1
docker compose -p $P logs --no-color --tail 200 gateway > "$out/gateway.log" 2>&1
$PY -m orchestrator.down $Y > "$out/down.log" 2>&1
cp logs/$id/*.jsonl "$out/" 2>/dev/null; rm -rf orchestrator/generated/$id
