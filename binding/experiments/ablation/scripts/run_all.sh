#!/usr/bin/env bash
# Serial (ONE topology at a time). Run from binding/harness. Arg: list file (default topologies.txt).
L=${1:-../experiments/ablation/topologies.txt}
while read -r id; do [ -n "$id" ] && ../experiments/ablation/scripts/run_one.sh "$id"; done < "$L"
echo ALLDONE
