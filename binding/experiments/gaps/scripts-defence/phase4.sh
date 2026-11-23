#!/usr/bin/env bash
# After rep2: status-code diagnostic of the perf failure cells (20 s each). From binding/harness.
D=$(cd ../experiments/defence && pwd)
until grep -q "REP2 DONE" $D/rep2_progress.log 2>/dev/null; do sleep 15; done
{ $D/scripts/diag_perf.sh bedge fastapi "1000"
  $D/scripts/diag_perf.sh da fastapi "500 1000"
  $D/scripts/diag_perf.sh borigin spring "500 1000 max"
  $D/scripts/diag_perf.sh bedge spring "max"
  $D/scripts/diag_perf.sh db spring "1000 max"
} >> $D/diag_progress.log 2>&1
echo "DIAG DONE $(date)" >> $D/diag_progress.log
