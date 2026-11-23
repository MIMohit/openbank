#!/usr/bin/env bash
# W18 ground truth: op(pi) per framework x override for ALL 17 base ops, direct to bh-exec-<fw>:v2
# (VERIFY_MODE=off), baselines only (oracle_spec section 2). Run from binding/harness. Copied from ext-routes/scripts/gt.sh.
set -uo pipefail
PY=orchestrator/.venv/bin/python
K=$(cd ../experiments/ablation && pwd)
S=$K/scripts
port=29890
mkdir -p "$K/groundtruth"
for fw in ${FWS:-fastapi spring rails laravel}; do
 for ov in off on; do
  port=$((port+1)); name=w18-gt-$fw-ov$ov; d=$K/groundtruth/raw/$fw-ov$ov
  rm -rf "$d"; mkdir -p "$d"
  docker rm -f $name >/dev/null 2>&1 || true
  docker run -d --name $name -m 700m -p 127.0.0.1:$port:8080 -e OVERRIDE=$ov -e VERIFY_MODE=off \
     -e ROUTES=v2 -e FRAMEWORK_TAG=$fw -e LOG_PATH=/logs/executor.jsonl -v "$d":/logs bh-exec-$fw:v2 >/dev/null
  for i in $(seq 1 150); do curl -s -o /dev/null --max-time 2 http://127.0.0.1:$port/api/v1/health && break; sleep 1; done
  $PY $S/ab_run_matrix.py --host-port $port --direct --cases $K/cases.jsonl --topology-id $name --out "$d/runner.jsonl" 2>>"$d/run.log"
  sleep 1
  $PY -m runner.build_groundtruth --runner "$d/runner.jsonl" --executor "$d/executor.jsonl" --framework $fw --out $K/groundtruth/$fw-ov$ov.jsonl 2>>"$d/run.log"
  docker inspect --format '{{.Image}}' $name > "$d/image_id.txt"
  docker rm -f $name >/dev/null
  echo "gt $fw ov$ov: $(wc -l < $K/groundtruth/$fw-ov$ov.jsonl) base ops; nonconformant: $(python3 -c "import json,sys;print(sum(1 for l in open(sys.argv[1]) if (r:=json.loads(l))['op_id']!=r['base_op_id'] or int(r['status'])>=400))" $K/groundtruth/$fw-ov$ov.jsonl)"
 done
done
