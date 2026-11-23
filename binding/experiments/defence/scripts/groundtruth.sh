#!/usr/bin/env bash
# Ground truth op(pi) for the v2 route space (CONTRACT §6): each baseline (depth-0) case sent directly
# to bh-exec-<fw>:v2 with VERIFY_MODE=off (adapted copy of kill/scripts/groundtruth.sh). Run from binding/harness.
set -euo pipefail
PY=orchestrator/.venv/bin/python
D=$(cd ../experiments/defence && pwd); port=28700
for fw in fastapi express spring aspnet; do
 for ov in off on; do
  port=$((port+1)); name=w17-gt-$fw-ov$ov; d=$D/groundtruth/raw/$fw-ov$ov
  rm -rf "$d"; mkdir -p "$d"
  python3 -c "import json,sys;[print(l.strip()) for l in open('$D/cases/ngx-$fw-ov$ov.jsonl') if json.loads(l).get('depth')==0 or not json.loads(l)['primitive_ids']]" > "$d/cases.jsonl"
  docker rm -f $name >/dev/null 2>&1 || true
  docker run -d --name $name -m 640m -p 127.0.0.1:$port:8080 -e OVERRIDE=$ov -e VERIFY_MODE=off \
     -e FRAMEWORK_TAG=$fw -e LOG_PATH=/logs/executor.jsonl -v "$d":/logs bh-exec-$fw:v2 >/dev/null
  for i in $(seq 1 120); do curl -s -o /dev/null --max-time 2 http://127.0.0.1:$port/api/v1/health && break; sleep 1; done
  $PY $D/scripts/ext_run_matrix.py --host-port $port --direct --topology-id $name --cases "$d/cases.jsonl" --out "$d/runner.jsonl"
  $PY -m runner.build_groundtruth --runner "$d/runner.jsonl" --executor "$d/executor.jsonl" --framework $fw --out $D/groundtruth/$fw-ov$ov.jsonl
  docker inspect --format '{{.Image}}' $name > "$d/image_id.txt"
  docker rm -f $name >/dev/null
 done
done
