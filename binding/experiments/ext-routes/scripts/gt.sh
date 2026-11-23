#!/usr/bin/env bash
# W15 ext-routes ground truth: op(pi) per framework x override, from a DIRECT run of the
# bh-exec-<fw>:v2 image (ROUTES=v2, VERIFY_MODE=off). oracle_spec §2. Run from binding/harness.
set -uo pipefail
PY=orchestrator/.venv/bin/python
K=$(cd ../experiments/ext-routes && pwd)
S=$K/scripts
port=29200
rm -rf "$K/groundtruth"; mkdir -p "$K/groundtruth"
for fw in fastapi express django go-chi spring aspnet rails laravel; do
 for ov in off on; do
  port=$((port+1)); name=w15r-gt-$fw-ov$ov; d=$K/groundtruth/raw/$fw-ov$ov
  rm -rf "$d"; mkdir -p "$d"
  docker rm -f $name >/dev/null 2>&1 || true
  docker run -d --name $name -m 500m -p 127.0.0.1:$port:8080 -e OVERRIDE=$ov -e VERIFY_MODE=off \
     -e ROUTES=v2 -e FRAMEWORK_TAG=$fw -e LOG_PATH=/logs/executor.jsonl -v "$d":/logs bh-exec-$fw:v2 >/dev/null
  for i in $(seq 1 120); do curl -s -o /dev/null --max-time 2 http://127.0.0.1:$port/api/v1/health && break; sleep 1; done
  $PY $S/ext_run_matrix.py --host-port $port --direct --cases $K/cases.jsonl --topology-id $name --out "$d/runner.jsonl" 2>>"$d/run.log"
  $PY -m runner.build_groundtruth --runner "$d/runner.jsonl" --executor "$d/executor.jsonl" --framework $fw --out $K/groundtruth/$fw-ov$ov.jsonl 2>>"$d/run.log"
  docker inspect --format '{{.Image}}' $name > "$d/image_id.txt"
  docker rm -f $name >/dev/null
  echo "gt $fw ov$ov: $(wc -l < $K/groundtruth/$fw-ov$ov.jsonl) base ops"
 done
done
