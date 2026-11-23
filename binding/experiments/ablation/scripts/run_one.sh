#!/usr/bin/env bash
# One W18 A1 topology: up (--stubs off) -> [digest gate hop] -> runner (variant minting) -> down -> correlate.
# Usage (from binding/harness): run_one.sh <topology-id> [outdir-root]   (adapted from ext-routes/scripts/run_one.sh)
set -uo pipefail
id=$1
K=$(cd ../experiments/ablation && pwd); ROOT=${2:-$K/runs}
S=$K/scripts
PY=orchestrator/.venv/bin/python
Y=$K/topologies/$id.yaml
fw=$(grep '^framework:' $Y | awk '{print $2}'); ov=$(grep '^override:' $Y | tr -d "'" | awk '{print $2}')
variant=$(echo "$id" | sed -E 's/^w18-(.*)-nginx-default-edge-.*/\1/')
case $variant in
  query) bind=query;; digest|digest-nogate) bind=digest;; query-digest) bind=query-digest;; *) bind=full;;
esac
gate=0; case $variant in digest|query-digest) gate=1;; esac
out=$ROOT/$id; rm -rf "$out"; mkdir -p "$out"
export BH_PROJECT_PREFIX=w18-bh-
P=w18-bh-$id
t0=$(date +%s)
cleanup() {
  docker rm -f w18-dg-$id >/dev/null 2>&1 || true
  $PY -m orchestrator.down $Y >> "$out/down.log" 2>&1
}
if ! $PY -m orchestrator.up $Y --stubs off --fresh-logs --timeout 300 > "$out/up.log" 2>&1; then
  echo "UP FAILED $id" | tee -a "$out/status.txt"; cleanup; exit 1
fi
if [ $gate = 1 ]; then
  conf=orchestrator/generated/$id/gateway/nginx.conf
  net=$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' $P-gateway-1 | awk '{print $1}')
  docker run -d --name w18-dg-$id --network $net --network-alias digestgate -m 128m \
     -v "$(pwd)/logs/$id":/logs -e LOG_PATH=/logs/digest_gate.jsonl bh-verifier:ablate \
     python -m verifier.digest_gate > "$out/gate.cid" 2>&1
  # in-place rewrite (keep the inode: the file is bind-mounted read-only into the gateway)
  new=$(sed 's#proxy_pass http://executor:8080;#proxy_pass http://digestgate:8081;#' $conf); printf '%s\n' "$new" > $conf
  sleep 2
  docker exec $P-gateway-1 nginx -t >> "$out/gate.log" 2>&1 && docker exec $P-gateway-1 nginx -s reload >> "$out/gate.log" 2>&1
  sleep 2
  grep -c digestgate $conf >> "$out/gate.log"
fi
docker compose -p $P images --format json > "$out/images.json" 2>/dev/null || true
$PY $S/ab_run_matrix.py --topology $Y --cases ${CASES:-$K/cases.jsonl} --bind $bind --out logs/$id/runner.jsonl > "$out/runner.stderr.log" 2>&1
rc=$?
sleep 1
docker compose -p $P logs --no-color --tail 400 gateway > "$out/gateway.log" 2>&1 || true
[ $gate = 1 ] && docker logs w18-dg-$id > "$out/gate.stdout.log" 2>&1
cleanup
cp logs/$id/*.jsonl "$out/"
mkdir -p "$out/generated" && cp -R orchestrator/generated/$id/. "$out/generated/" && rm -rf orchestrator/generated/$id
$PY -m oracle.correlate --log-dir "$out" --topology $Y --ground-truth $K/groundtruth/$fw-ov$ov.jsonl \
    --summary-csv $ROOT/summary.csv > "$out/correlate.log" 2>&1
echo "$id variant=$variant bind=$bind gate=$gate runner_rc=$rc secs=$(( $(date +%s)-t0 )) $(tail -1 $out/runner.stderr.log)" | tee "$out/status.txt"
