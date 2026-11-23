#!/usr/bin/env bash
# Resume of phase2 perf after the first da-fastapi run was invalidated (host sleep + token expiry; runs_invalid/perf_sleep_token_expiry).
# Wrapped in caffeinate -i so the host cannot idle-sleep mid-run. From binding/harness.
D=$(cd ../experiments/defence && pwd)
for pair in da:fastapi db:fastapi bedge:spring borigin:spring da:spring db:spring; do
  MAXDUR=30s $D/scripts/run_perf.sh ${pair%%:*} ${pair##*:} 5 60s
done >> $D/perf_progress.log 2>&1
echo "PHASE2 DONE $(date)" >> $D/perf_progress.log
