#!/usr/bin/env bash
# Sample the ZT Controller container's CPU and memory while a workload runs.
#
# Table 4 (§7.3) reports CPU/memory overhead per configuration, and nothing in
# the testbed measured it: the JSONL records per-request latency only.  This
# polls `docker stats` for the controller container and appends one CSV row per
# sample, so the analysis can report mean/peak per configuration.
#
# Usage: scripts/sample_resources.sh <run_label> <out_csv> [container]
# Terminate with SIGTERM/SIGINT; the Makefile starts it in the background and
# kills it when the workload finishes.
set -uo pipefail

LABEL="${1:?run label required}"
OUT="${2:?output csv required}"
CONTAINER="${3:-open-bank-zt-controller-1}"

mkdir -p "$(dirname "$OUT")"
if [[ ! -s "$OUT" ]]; then
  echo "run_label,ts,cpu_percent,mem_mib,mem_percent" > "$OUT"
fi

running=1
trap 'running=0' TERM INT

while [[ $running -eq 1 ]]; do
  # {{.CPUPerc}} -> "12.34%", {{.MemUsage}} -> "45.6MiB / 7.66GiB"
  line=$(docker stats --no-stream --format '{{.CPUPerc}};{{.MemUsage}};{{.MemPerc}}' "$CONTAINER" 2>/dev/null) || line=""
  if [[ -n "$line" ]]; then
    cpu=${line%%;*}
    rest=${line#*;}
    mem_usage=${rest%%;*}
    mem_pct=${rest##*;}
    mem_raw=${mem_usage%% *}
    # Normalise the memory figure to MiB regardless of the unit docker chose.
    num=$(echo "$mem_raw" | sed 's/[A-Za-z]*$//')
    unit=$(echo "$mem_raw" | sed 's/^[0-9.]*//')
    case "$unit" in
      GiB|GB) mem_mib=$(awk -v n="$num" 'BEGIN{printf "%.3f", n*1024}') ;;
      KiB|kB) mem_mib=$(awk -v n="$num" 'BEGIN{printf "%.3f", n/1024}') ;;
      B)      mem_mib=$(awk -v n="$num" 'BEGIN{printf "%.6f", n/1048576}') ;;
      *)      mem_mib="$num" ;;
    esac
    printf '%s,%s,%s,%s,%s\n' \
      "$LABEL" "$(date +%s.%N)" "${cpu%\%}" "$mem_mib" "${mem_pct%\%}" >> "$OUT"
  fi
  sleep 1
done
