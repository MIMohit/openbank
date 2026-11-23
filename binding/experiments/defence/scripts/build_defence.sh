#!/bin/sh
# Build bh-exec-<fw>:defence from the patched copies under build/src/executors (one at a time).
set -eu
cd "$(dirname "$0")/../build/src/executors"
mkdir -p ../../logs
for fw in ${@:-fastapi express spring aspnet}; do
  echo "== $fw $(date)"; docker build -t bh-exec-$fw:defence $fw > ../../logs/build-$fw.log 2>&1 && echo "built $fw" || { echo "FAILED $fw"; tail -20 ../../logs/build-$fw.log; }
  docker image inspect bh-exec-$fw:defence --format '{{.Id}}' >> ../../logs/build-$fw.log 2>&1 || true
done
