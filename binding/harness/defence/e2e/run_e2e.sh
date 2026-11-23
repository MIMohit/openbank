#!/bin/sh
# Usage (from binding/harness): defence/e2e/run_e2e.sh <fw>   (needs image w11-exec-<fw>:db built from the patched executor)
# Starts w11-e2e-verifier + two executors (DEFENCE=db and DEFENCE=off, both OVERRIDE=on, VERIFY_MODE=off)
# on network w11-e2e, runs the client, writes defence/e2e/results/<fw>.json, then tears everything down.
set -eu
FW=$1; KEY=w11-e2e-key; NET=w11-e2e; LOGS="$PWD/defence/e2e/results/logs-$FW"
cleanup() { docker rm -f w11-e2e-verifier w11-e2e-$FW-db w11-e2e-$FW-off >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup; rm -rf "$LOGS"; mkdir -p "$LOGS/v" "$LOGS/db" "$LOGS/off"
docker network create $NET >/dev/null
docker run -d --name w11-e2e-verifier --network $NET --memory 256m -p 127.0.0.1:19111:9100 \
  -e VIEW_MAC=on -e VIEW_MAC_KEY=$KEY -e HTU_CANON=rfc3986 -v "$LOGS/v:/logs" bh-verifier:latest >/dev/null
for m in db off; do
  port=$([ $m = db ] && echo 19112 || echo 19113)
  docker run -d --name w11-e2e-$FW-$m --network $NET --memory 512m -p 127.0.0.1:$port:8080 \
    -e DEFENCE=$m -e VIEW_MAC_KEY=$KEY -e OVERRIDE=on -e VERIFY_MODE=off -e FRAMEWORK_TAG=$FW \
    -v "$LOGS/$m:/logs" w11-exec-$FW:db >/dev/null
done
for port in 19111 19112 19113; do
  i=0; until curl -s -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null; do i=$((i+1)); [ $i -gt 120 ] && { echo "port $port not up"; exit 1; }; sleep 1; done
done
PYTHONPATH=. verifier/.venv/bin/python defence/e2e/e2e_client.py --fw $FW --verifier 127.0.0.1:19111 \
  --db 127.0.0.1:19112 --off 127.0.0.1:19113 > defence/e2e/results/$FW.json
docker image inspect w11-exec-$FW:db --format '{{.Id}}' > defence/e2e/results/$FW.image.txt
echo "wrote defence/e2e/results/$FW.json"
