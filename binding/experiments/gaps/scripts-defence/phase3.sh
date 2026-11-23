#!/usr/bin/env bash
# Replication 2 of the whole E7/E8 sweep (determinism) into runs_rep2/, after perf. From binding/harness.
D=$(cd ../experiments/defence && pwd)
until grep -q "PHASE2 DONE" $D/perf_progress.log 2>/dev/null; do sleep 15; done
for wl in aleak e4; do
  while read -r cfg src id; do [ -z "$cfg" ] && continue
    OUT_ROOT=runs_rep2 $D/scripts/run_one.sh $wl $cfg $src $id
  done < $D/worklist_$wl.txt
done >> $D/rep2_progress.log 2>&1
echo "REP2 DONE $(date)" >> $D/rep2_progress.log
