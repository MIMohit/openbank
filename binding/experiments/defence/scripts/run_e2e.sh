#!/bin/sh
# Copy of harness/defence/e2e/run_e2e.sh (W11) adapted for W17: image bh-exec-<fw>:defence (v2 routes + D-B),
# names w17-e2e-*, ports 19211-19213, results under experiments/defence/results/e2e/. Run from binding/harness.
set -eu
FW=$1; KEY=w17-e2e-key; NET=w17-e2e; R="$PWD/../experiments/defence/results/e2e"; LOGS="$R/logs-$FW"
cleanup() { docker rm -f w17-e2e-verifier w17-e2e-$FW-db w17-e2e-$FW-off >/dev/null 2>&1 || true; docker network rm $NET >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup; rm -rf "$LOGS"; mkdir -p "$LOGS/v" "$LOGS/db" "$LOGS/off"
docker network create $NET >/dev/null
docker run -d --name w17-e2e-verifier --network $NET --network-alias verifier --memory 256m -p 127.0.0.1:19211:9100 \
  -e VIEW_MAC=on -e VIEW_MAC_KEY=$KEY -e HTU_CANON=rfc3986 -v "$LOGS/v:/logs" bh-verifier:latest >/dev/null
for m in db off; do
  port=$([ $m = db ] && echo 19212 || echo 19213)
  docker run -d --name w17-e2e-$FW-$m --network $NET --memory 512m -p 127.0.0.1:$port:8080 \
    -e DEFENCE=$m -e VIEW_MAC_KEY=$KEY -e OVERRIDE=on -e VERIFY_MODE=off -e FRAMEWORK_TAG=$FW \
    -v "$LOGS/$m:/logs" bh-exec-$FW:defence >/dev/null
done
for port in 19211 19212 19213; do
  i=0; until curl -s -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null; do i=$((i+1)); [ $i -gt 120 ] && { echo "port $port not up"; exit 1; }; sleep 1; done
done
PYTHONPATH=. verifier/.venv/bin/python defence/e2e/e2e_client.py --fw $FW --verifier 127.0.0.1:19211 \
  --db 127.0.0.1:19212 --off 127.0.0.1:19213 > "$R/$FW.json"
docker image inspect bh-exec-$FW:defence --format '{{.Id}}' > "$R/$FW.image.txt"
echo "wrote $R/$FW.json"
