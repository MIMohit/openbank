#!/usr/bin/env bash
# Run W4's conformance script against one W5 executor image in six configurations:
#   OVERRIDE in {off,on} x VERIFY_MODE in {off,origin-raw,origin-routed}
# Usage: w5_conformance.sh <fw> [outdir]
# Uses: docker network w5-net, container w5-verifier (W4's stub_verifier.py, alias "verifier"),
#       container w5-exec-<fw> on host port 18580. Everything is torn down at the end.
set -u
FW="$1"
HERE="$(cd "$(dirname "$0")" && pwd)"
EXE="$(cd "$HERE/../.." && pwd)"
OUT="${2:-$EXE/$FW/conformance-out}"
CONF="$EXE/conformance"
PORT=18580
mkdir -p "$OUT"
rm -rf "$OUT"/*
docker network create w5-net >/dev/null 2>&1 || true
docker rm -f w5-verifier "w5-exec-$FW" >/dev/null 2>&1 || true
mkdir -p "$OUT/stub"
docker run -d --name w5-verifier --network w5-net --network-alias verifier --memory 128m \
  -v "$CONF:/conf:ro" -v "$OUT/stub:/stub" python:3.12-slim \
  python /conf/stub_verifier.py --port 9100 --log /stub/verifier_stub.jsonl >/dev/null
rc_all=0
for OV in off on; do
  for VM in off origin-raw origin-routed; do
    tag="ov${OV}_${VM}"
    mkdir -p "$OUT/$tag/logs"
    docker rm -f "w5-exec-$FW" >/dev/null 2>&1 || true
    docker run -d --name "w5-exec-$FW" --network w5-net --memory 768m -p 127.0.0.1:$PORT:8080 \
      -e OVERRIDE=$OV -e VERIFY_MODE=$VM -e FRAMEWORK_TAG=$FW \
      -v "$OUT/$tag/logs:/logs" "bh-exec-$FW:latest" >/dev/null
    extra=(--override "$OV")
    if [ "$VM" != off ]; then extra+=(--verify-mode "$VM" --stub-log "$OUT/stub/verifier_stub.jsonl"); fi
    # wait for health (JVM / .NET start-up)
    for i in $(seq 1 90); do
      curl -s -o /dev/null -H 'Host: api.bench.test' "http://127.0.0.1:$PORT/api/v1/health" && break; sleep 1
    done
    echo "=== $FW OVERRIDE=$OV VERIFY_MODE=$VM" | tee "$OUT/$tag/result.txt"
    python3 "$CONF/run_conformance.py" "http://127.0.0.1:$PORT" --framework "$FW" \
      --log-file "$OUT/$tag/logs/executor.jsonl" "${extra[@]}" --json "$OUT/$tag/result.json" \
      | tee -a "$OUT/$tag/result.txt"
    rc=${PIPESTATUS[0]}; [ $rc -ne 0 ] && rc_all=1
    docker logs "w5-exec-$FW" > "$OUT/$tag/container.log" 2>&1
    docker rm -f "w5-exec-$FW" >/dev/null
  done
done
docker rm -f w5-verifier >/dev/null
docker network rm w5-net >/dev/null 2>&1 || true
exit $rc_all
