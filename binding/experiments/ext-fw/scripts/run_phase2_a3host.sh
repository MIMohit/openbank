#!/usr/bin/env bash
# Phase 2: after the determinism reruns finish, run the 8 nginx-default-origin topologies
# with the Host-preserving work-around (up_hostfix.py) so the A3 nginx-origin result is not
# masked by nginx's default Host-rewrite artefact. One topology at a time. Output -> runs_a3host/.
set -uo pipefail
K=$(cd "$(dirname "$0")/.." && pwd)
HARNESS=$(cd "$K/../.." && pwd)/harness
LOG=$K/runs_a3host/_driver.log
mkdir -p "$K/runs_a3host"
# wait for the rerun driver to signal DONE
for _ in $(seq 1 720); do
  grep -q 'rerun driver DONE' "$K/reruns/_driver.log" 2>/dev/null && break
  sleep 15
done
echo "=== phase2 a3host start $(date -u +%FT%TZ) ===" | tee -a "$LOG"
while read -r tid; do
  [ -z "$tid" ] && continue
  echo "--- $tid $(date -u +%FT%TZ) ---" | tee -a "$LOG"
  (cd "$HARNESS" && bash "$K/scripts/run_one_hostfix.sh" "$tid" "$K/runs_a3host") >> "$LOG" 2>&1
  echo "    done $(date -u +%FT%TZ)" | tee -a "$LOG"
done < /tmp/w14_nginx_origin.txt
echo "=== phase2 a3host DONE $(date -u +%FT%TZ) ===" | tee -a "$LOG"
