#!/usr/bin/env bash
# W15 ext-routes conformance: run run_conformance.py --v2 against bh-exec-<fw>:v2 images in
# every OVERRIDE x VERIFY_MODE config (2 x 3 = 6). All executors run with ROUTES=v2.
# Usage: ./run_v2_matrix.sh [<fw> ...]   (default: all 8)
# Containers are named w15-conf-<fw>-<cfg> and removed afterwards. Needs Docker Desktop
# (host.docker.internal) for the stub verifier, which runs on the host.
# Env: BASE_PORT (default 18600), STUB_PORT (default 19600).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/../conformance-out
mkdir -p "$OUT"
FWS=("$@"); [ ${#FWS[@]} -eq 0 ] && FWS=(fastapi express django go-chi spring aspnet rails laravel)
STUB_PORT=${STUB_PORT:-19600}
: > "$OUT/stub_${STUB_PORT}.jsonl"
python3 "$HERE/stub_verifier.py" --port "$STUB_PORT" --log "$OUT/stub_${STUB_PORT}.jsonl" >/dev/null 2>&1 &
STUB=$!
trap 'kill $STUB 2>/dev/null' EXIT
port=${BASE_PORT:-18600}
rc=0
for fw in "${FWS[@]}"; do
  for cfg in ovoff-verifyoff ovoff-originraw ovoff-originrouted ovon-verifyoff ovon-originraw ovon-originrouted; do
    OV=off; VM=off; extra=(--v2)
    case $cfg in
      ovoff-verifyoff)    OV=off; VM=off ;;
      ovoff-originraw)    OV=off; VM=origin-raw;    extra+=(--verify-mode origin-raw --stub-log "$OUT/stub_${STUB_PORT}.jsonl") ;;
      ovoff-originrouted) OV=off; VM=origin-routed; extra+=(--verify-mode origin-routed --stub-log "$OUT/stub_${STUB_PORT}.jsonl") ;;
      ovon-verifyoff)     OV=on;  VM=off;           extra+=(--override on) ;;
      ovon-originraw)     OV=on;  VM=origin-raw;    extra+=(--override on --verify-mode origin-raw --stub-log "$OUT/stub_${STUB_PORT}.jsonl") ;;
      ovon-originrouted)  OV=on;  VM=origin-routed; extra+=(--override on --verify-mode origin-routed --stub-log "$OUT/stub_${STUB_PORT}.jsonl") ;;
    esac
    [ "$OV" = on ] && [[ " ${extra[*]} " != *" --override "* ]] && extra+=(--override on)
    name="w15-conf-${fw}-${cfg}"
    logdir="$OUT/${fw}/${cfg}"; rm -rf "$logdir"; mkdir -p "$logdir"
    port=$((port+1))
    docker rm -f "$name" >/dev/null 2>&1
    docker run -d --name "$name" --memory 300m -p "127.0.0.1:${port}:8080" \
      -e OVERRIDE=$OV -e VERIFY_MODE=$VM -e ROUTES=v2 -e FRAMEWORK_TAG=$fw \
      -e VERIFIER_URL=http://host.docker.internal:${STUB_PORT}/authz/orig \
      -v "$logdir:/logs" "bh-exec-${fw}:v2" >/dev/null
    if [ "$VM" = origin-raw ]; then sink=(--docker-logs "$name"); else sink=(--log-file "$logdir/executor.jsonl"); fi
    echo "### ${fw} / ${cfg} (OVERRIDE=$OV VERIFY_MODE=$VM)"
    python3 "$HERE/run_conformance.py" "http://127.0.0.1:${port}" --framework "$fw" "${sink[@]}" "${extra[@]}" \
      --json "$logdir/result.json" | tail -2 || rc=1
    docker logs "$name" 2>&1 | grep -v '^{' | head -5 > "$logdir/container_stderr.txt"
    docker rm -f "$name" >/dev/null
  done
done
echo "matrix rc=$rc"
exit $rc
