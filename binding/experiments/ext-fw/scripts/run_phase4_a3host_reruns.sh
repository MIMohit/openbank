#!/usr/bin/env bash
# Phase 4: 3x determinism reruns for the Host-corrected nginx-origin A3 topologies (runs_a3host/).
# Uses up_hostfix (so the Host fix is applied each rep) and reads hits from runs_a3host/.
set -uo pipefail
K=$(cd "$(dirname "$0")/.." && pwd)
HARNESS=$(cd "$K/../.." && pwd)/harness
PY=$HARNESS/orchestrator/.venv/bin/python
LOG=$K/reruns_a3host/_driver.log
mkdir -p "$K/reruns_a3host"
echo "=== phase4 a3host reruns start $(date -u +%FT%TZ) ===" | tee -a "$LOG"
while read -r tid; do
  [ -z "$tid" ] && continue
  echo "--- $tid $(date -u +%FT%TZ) ---" | tee -a "$LOG"
  (cd "$HARNESS" && "$PY" "$K/scripts/rerun_hc.py" "$tid" --reps 3 --runs-dir runs_a3host --reruns-dir reruns_a3host) >> "$LOG" 2>&1
  echo "    rc=$? done $(date -u +%FT%TZ)" | tee -a "$LOG"
done < /tmp/w14_nginx_origin.txt
echo "=== phase4 a3host reruns DONE $(date -u +%FT%TZ) ===" | tee -a "$LOG"
