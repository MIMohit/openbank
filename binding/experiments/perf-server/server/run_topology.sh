#!/usr/bin/env bash
# Runs ON the server (from /root/bhperf). One topology: up -> sanity -> 20 s warm-up -> RUNS x DUR per level, 30 s
# cool-down after every run -> down. Mirrors experiments/defence/scripts/run_perf.sh (same load.js, same k6 1.3.0,
# same request, same constant-arrival-rate executor), with the server caps and no published ports.
# Usage: run_topology.sh <name e.g. bedge-fastapi> "<levels e.g. 50 100>" <runs> <dur>
# Needs /root/bhperf/tokens/<name>.env with AUTHZ=... PROOF=... (minted on the Mac right before).
set -uo pipefail
R=/root/bhperf; name=$1; LEVELS=$2; RUNS=${3:-5}; DUR=${4:-60s}; COOL=${COOL:-30}
C=$R/compose/$name/docker-compose.yml; P=bhperf-$name; out=$R/results/$name
mkdir -p $out $R/logs/$name; chmod 777 $out $R/logs/$name
log() { echo "$(date -u +%FT%TZ) $name $*" | tee -a $R/runner.log; }
aborted() { [ -e $R/ABORT ]; }
down() { docker compose -p $P -f $C logs --no-color --tail 50 > $out/compose_tail.log 2>&1
         docker compose -p $P -f $C down --timeout 10 > $out/down.log 2>&1; }
cpustat() { # cgroup v2 cpu.stat + memory.peak of our containers only (read-only files)
  for n in bhperf-gateway bhperf-verifier bhperf-executor; do
    id=$(docker inspect -f '{{.Id}}' $n 2>/dev/null) || continue
    d=$(ls -d /sys/fs/cgroup/system.slice/docker-$id.scope 2>/dev/null) || continue
    echo "$n $(tr '\n' ' ' < $d/cpu.stat) mem_current=$(cat $d/memory.current) mem_peak=$(cat $d/memory.peak 2>/dev/null)"
  done; }
k6() { docker run --rm --name bhperf-k6 --label bhperf=1 --network bhperf-net --cpus 0.2 -m 256m --restart no \
         --log-driver json-file --log-opt max-size=10m -v $R/perf:/scripts:ro -v $out:/out \
         -e TARGET=gateway:8000 -e AUTHZ="$AUTHZ" -e PROOF="$PROOF" "$@"; }

aborted && { log "ABORT file present, not starting"; exit 2; }
./guard.sh check > /dev/null || { log "pre-check violation: $(tail -1 $R/guard.log)"; exit 2; }
set -a; . $R/tokens/$name.env; set +a
log "up"
docker compose -p $P -f $C up -d > $out/up.log 2>&1 || { log "UP FAILED"; cat $out/up.log; down; exit 1; }
docker compose -p $P -f $C images --format json > $out/images.json 2>/dev/null
code=000
for i in $(seq 1 90); do   # up to ~180 s (spring under 0.3 CPU starts slowly)
  code=$(docker exec bhperf-gateway wget -S -O /dev/null --header 'Host: api.bench.test' \
      --header "Authorization: $AUTHZ" --header "DPoP: $PROOF" http://127.0.0.1:8000/api/v1/accounts/acc-alice-1 2>&1 \
      | awk '/HTTP\//{c=$2}END{print c+0}')
  [ "$code" = 200 ] && break; sleep 2
done
echo "sanity status=$code after_tries=$i" | tee $out/sanity.txt
[ "$code" = 200 ] || { log "SANITY FAILED $code"; down; exit 1; }
log "warmup 20s @100"
k6 -e MODE=rate -e RATE=100 -e DUR=20s bhperf-k6:amd64 run -q /scripts/load.js > $out/warmup.log 2>&1
for lvl in $LEVELS; do
  for r in $(seq 1 $RUNS); do
    tag=$lvl-r$r
    aborted && { log "ABORT before $tag"; down; exit 3; }
    ./guard.sh check > /dev/null || { log "pre-run violation before $tag: $(tail -1 $R/guard.log)"; down; exit 3; }
    for w in $(seq 1 36); do   # quiet gate (added after abort 1): start only when 1-min load < 0.8 (max 180 s)
      awk -v l=$(cut -d' ' -f1 /proc/loadavg) 'BEGIN{exit !(l<0.8)}' && break; sleep 5; done
    echo "$tag gate_wait_s=$(( (w-1)*5 )) load=$(cut -d' ' -f1-3 /proc/loadavg)" >> $out/gate.txt
    cpustat > $out/$tag.cpu_before.txt
    log "run $tag"
    k6 -e MODE=rate -e RATE=$lvl -e DUR=$DUR bhperf-k6:amd64 run -q --out csv=/out/$tag.csv \
       --summary-export /out/$tag.summary.json /scripts/load.js > $out/$tag.log 2>&1
    echo "k6_exit=$?" >> $out/$tag.log
    cpustat > $out/$tag.cpu_after.txt
    aborted && { log "ABORT during $tag (run discarded)"; mv $out/$tag.csv $out/$tag.csv.aborted 2>/dev/null; down; exit 3; }
    gzip -f $out/$tag.csv
    sleep $COOL
  done
done
du -sh $R/logs/$name > $out/harness_logs_size.txt 2>&1
down; rm -rf $R/logs/$name
log "done"
