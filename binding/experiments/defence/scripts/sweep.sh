#!/usr/bin/env bash
# Sequential sweep (ONE topology up at a time). Usage (from binding/harness): sweep.sh <worklist> <kind>
set -uo pipefail
D=$(cd ../experiments/defence && pwd)
skew=$(( $(docker run --rm --name w17-clock python:3.12.16-slim-trixie date +%s) - $(date +%s) ))
echo "docker clock skew ${skew}s" | tee -a $D/sweep_progress.log
while read -r cfg src id; do
  [ -z "$cfg" ] && continue
  if [ -f "$D/runs/$cfg/$id/status.txt" ] && grep -q runner_rc=0 "$D/runs/$cfg/$id/status.txt"; then continue; fi
  $D/scripts/run_one.sh $2 $cfg $src $id >> $D/sweep_progress.log 2>&1
done < $1
echo "SWEEP DONE $1 $(date)" >> $D/sweep_progress.log
