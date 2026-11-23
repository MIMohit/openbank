#!/usr/bin/env bash
# Runs run_conformance.py against bh-exec-<fw>:latest images in three configurations.
# Usage: ./run_docker_matrix.sh <tag-prefix> <fw> [<fw> ...]     e.g. ./run_docker_matrix.sh w4 fastapi express
# Containers are named <tag-prefix>-<fw>-<cfg> and removed afterwards. Needs Docker Desktop
# (host.docker.internal) for the stub verifier, which runs on the host.
# Env: BASE_PORT (default 18480; host ports BASE_PORT+1..), STUB_PORT (default 19100). Pick distinct
# values if another worker runs the matrix at the same time.
set -u
PFX=$1; shift
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/out
mkdir -p "$OUT"
STUB_PORT=${STUB_PORT:-19100}
: > "$OUT/stub_${STUB_PORT}.jsonl"
python3 "$HERE/stub_verifier.py" --port "$STUB_PORT" --log "$OUT/stub_${STUB_PORT}.jsonl" >/dev/null 2>&1 &
STUB=$!
trap 'kill $STUB 2>/dev/null' EXIT
port=${BASE_PORT:-18480}
rc=0
for fw in "$@"; do
  for cfg in "ovoff-verifyoff" "ovon-originraw" "ovon-originrouted"; do
    case $cfg in
      ovoff-verifyoff)   OV=off; VM=off; extra=(--override off) ;;
      ovon-originraw)    OV=on;  VM=origin-raw;    extra=(--override on --verify-mode origin-raw --stub-log "$OUT/stub_${STUB_PORT}.jsonl") ;;
      ovon-originrouted) OV=on;  VM=origin-routed; extra=(--override on --verify-mode origin-routed --stub-log "$OUT/stub_${STUB_PORT}.jsonl") ;;
    esac
    name="${PFX}-${fw}-${cfg}"
    logdir="$OUT/${fw}/${cfg}"; rm -rf "$logdir"; mkdir -p "$logdir"
    port=$((port+1))
    docker rm -f "$name" >/dev/null 2>&1
    docker run -d --name "$name" --memory 256m -p "127.0.0.1:${port}:8080" \
      -e OVERRIDE=$OV -e VERIFY_MODE=$VM -e VERIFIER_URL=http://host.docker.internal:${STUB_PORT}/authz/orig \
      -v "$logdir:/logs" "bh-exec-${fw}:latest" >/dev/null
    # log sink alternates: file for verifyoff/originrouted, docker stdout for originraw
    if [ "$cfg" = "ovon-originraw" ]; then sink=(--docker-logs "$name"); else sink=(--log-file "$logdir/executor.jsonl"); fi
    echo "### ${fw} / ${cfg} (OVERRIDE=$OV VERIFY_MODE=$VM, logs via ${sink[0]})"
    python3 "$HERE/run_conformance.py" "http://127.0.0.1:${port}" --framework "$fw" "${sink[@]}" "${extra[@]}" \
      --json "$logdir/result.json" || rc=1
    docker logs "$name" 2>&1 | grep -v '^{' | head -5 > "$logdir/container_stderr.txt"
    docker rm -f "$name" >/dev/null
  done
done
exit $rc
