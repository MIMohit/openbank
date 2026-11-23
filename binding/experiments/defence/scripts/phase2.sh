#!/usr/bin/env bash
# After FRR: E8 full-corpus B-edge vs B-optional (4 runs), then perf (8 stacks). From binding/harness.
D=$(cd ../experiments/defence && pwd)
until grep -q "FRR DONE" $D/frr_progress.log; do sleep 10; done
for fw in fastapi express; do for cfg in bedge bopt; do
  TOPO_DIR=e8full CASES=$D/cases/full-v2-depth1.jsonl $D/scripts/run_one.sh aleak $cfg full w17-e8full-$cfg-ngx-$fw-ovon
done; done >> $D/e8full_progress.log 2>&1
for fw in fastapi spring; do for cfg in bedge borigin da db; do
  MAXDUR=30s $D/scripts/run_perf.sh $cfg $fw 5 60s
done; done >> $D/perf_progress.log 2>&1
echo "PHASE2 DONE $(date)" >> $D/perf_progress.log
