#!/usr/bin/env bash
# Ground truth per framework x override via runner --direct (CONTRACT §6, oracle_spec §2).
# Also sends the full depth-1 matrix directly (--direct-all) as a framework-only reference map.
# W13: all 8 frameworks (the kill experiment only built fastapi/express/spring/aspnet).
# Run from binding/harness.
set -euo pipefail
PY=orchestrator/.venv/bin/python
K=../experiments/ext-gw
port=29300
for fw in fastapi express django go-chi spring aspnet rails laravel; do
 for ov in off on; do
  port=$((port+1)); name=w13-gt-$fw-ov$ov; d=$(cd $K && pwd)/groundtruth/raw/$fw-ov$ov
  rm -rf "$d"; mkdir -p "$d"
  docker rm -f $name >/dev/null 2>&1 || true
  docker run -d --name $name -m 640m -p 127.0.0.1:$port:8080 -e OVERRIDE=$ov -e VERIFY_MODE=off \
     -e FRAMEWORK_TAG=$fw -e LOG_PATH=/logs/executor.jsonl -v "$d":/logs bh-exec-$fw:latest >/dev/null
  ok=0
  for i in $(seq 1 120); do curl -s -o /dev/null --max-time 2 http://127.0.0.1:$port/api/v1/health && { ok=1; break; }; sleep 1; done
  if [ $ok -ne 1 ]; then echo "GT HEALTH FAIL $name"; docker logs --tail 40 $name || true; docker rm -f $name >/dev/null; exit 1; fi
  $PY -m runner.run_matrix --host-port $port --direct --topology-id $name --minter w3 --out "$d/runner.jsonl"
  $PY -m runner.build_groundtruth --runner "$d/runner.jsonl" --executor "$d/executor.jsonl" --framework $fw --out $K/groundtruth/$fw-ov$ov.jsonl
  cp "$d/executor.jsonl" "$d/executor.baseline.jsonl"; : > "$d/executor.jsonl"
  $PY -m runner.run_matrix --host-port $port --direct --direct-all --topology-id $name-all --minter w3 --out "$d/runner.all.jsonl"
  mv "$d/executor.jsonl" "$d/executor.all.jsonl"
  docker inspect --format '{{.Image}}' $name > "$d/image_id.txt"
  docker rm -f $name >/dev/null
  echo "GT done $fw ov$ov"
 done
done
