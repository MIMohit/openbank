#!/usr/bin/env bash
# Run every ext-fw topology serially (ONE up at a time), via run_one.sh.
# Usage (from binding/harness): run_all.sh <topologies-list-file>
set -uo pipefail
list=$1
S=$(dirname "$0")
n=0; tot=$(grep -c . "$list")
while read -r id; do
  [ -z "$id" ] && continue
  n=$((n+1))
  echo "[$n/$tot] $(date +%H:%M:%S) $id"
  bash "$S/run_one.sh" "$id" || echo "  !! run_one failed for $id"
done < "$list"
echo "ALL DONE ($n topologies)"
