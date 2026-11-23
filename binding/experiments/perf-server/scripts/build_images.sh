#!/usr/bin/env bash
# Cross-build linux/amd64 images LOCALLY (Mac, buildx + QEMU) from the same sources as the laptop images.
#   bhperf-verifier:amd64         <- binding/harness/verifier/Dockerfile        (laptop: bh-verifier:latest)
#   bhperf-exec-<fw>:amd64-v2     <- binding/harness/executors/<fw> ROUTES=v2   (laptop: bh-exec-<fw>:v2)
#   bhperf-exec-<fw>:amd64-def    <- experiments/defence/build/src/executors/<fw> (laptop: bh-exec-<fw>:defence)
#   bhperf-nginx:amd64            <- FROM nginx:1.30.7-alpine (amd64 variant)
#   bhperf-k6:amd64               <- FROM grafana/k6:1.3.0 (amd64 variant)
set -euo pipefail
B=$(cd "$(dirname "$0")/../../.." && pwd); L=$(cd "$(dirname "$0")/.." && pwd)/build; mkdir -p $L
P="--platform linux/amd64 --load"
bx() { local t=$1; shift; echo "== $t $(date)"; docker buildx build $P -t $t "$@" > $L/build-${t//[:\/]/_}.log 2>&1 && echo "ok $t" || { echo "FAIL $t"; tail -30 $L/build-${t//[:\/]/_}.log; exit 1; }; }
bx bhperf-verifier:amd64 -f $B/harness/verifier/Dockerfile $B/harness
bx bhperf-exec-fastapi:amd64-v2 --build-arg ROUTES=v2 $B/harness/executors/fastapi
bx bhperf-exec-fastapi:amd64-def $B/experiments/defence/build/src/executors/fastapi
bx bhperf-exec-spring:amd64-v2 --build-arg ROUTES=v2 $B/harness/executors/spring
bx bhperf-exec-spring:amd64-def $B/experiments/defence/build/src/executors/spring
# Base images are wrapped (FROM-only Dockerfiles) so the laptop's own arm64 nginx/k6 tags are never replaced.
bx bhperf-nginx:amd64 $L/wrap-nginx
bx bhperf-k6:amd64 $L/wrap-k6
for t in bhperf-verifier:amd64 bhperf-exec-fastapi:amd64-v2 bhperf-exec-fastapi:amd64-def bhperf-exec-spring:amd64-v2 bhperf-exec-spring:amd64-def bhperf-nginx:amd64 bhperf-k6:amd64; do
  docker image inspect $t --format "$t {{.Id}} {{.Architecture}} {{.Os}} {{.Created}} {{index .RepoDigests 0}}" 2>/dev/null || docker image inspect $t --format "$t {{.Id}} {{.Architecture}} {{.Os}} {{.Created}}"
done | tee $L/images_local.txt
