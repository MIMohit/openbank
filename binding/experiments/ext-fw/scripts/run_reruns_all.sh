#!/usr/bin/env bash
# Drive determinism reruns (oracle_spec §10) for every ext-fw topology that had >=1 hit.
# One topology up at a time (rerun.py serialises reps; this serialises topologies).
# Usage:  run_reruns_all.sh <list-file>
set -uo pipefail
LIST=${1:?need list file}
K=$(cd "$(dirname "$0")/.." && pwd)
HARNESS=$(cd "$K/../.." && pwd)/harness
PY=$HARNESS/orchestrator/.venv/bin/python
LOG=$K/reruns/_driver.log
mkdir -p "$K/reruns"
echo "=== rerun driver start $(date -u +%FT%TZ)  topologies=$(wc -l < "$LIST") ===" | tee -a "$LOG"
i=0; n=$(wc -l < "$LIST" | tr -d ' ')
while read -r tid; do
  [ -z "$tid" ] && continue
  i=$((i+1))
  echo "--- [$i/$n] $tid  $(date -u +%FT%TZ) ---" | tee -a "$LOG"
  (cd "$HARNESS" && "$PY" "$K/scripts/rerun_hc.py" "$tid" --reps 3) >> "$LOG" 2>&1
  echo "    rc=$? done $(date -u +%FT%TZ)" | tee -a "$LOG"
done < "$LIST"
echo "=== rerun driver DONE $(date -u +%FT%TZ) ===" | tee -a "$LOG"
