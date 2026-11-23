#!/usr/bin/env bash
# After A1 (runs_all.log has ALLDONE): aspnet ground truth, then A5 G2 strict/controls, then E4 strict. Serial.
cd /Users/mimohit/openbank/binding/harness
K=../experiments/ablation
until grep -q ALLDONE $K/runs_all.log; do sleep 20; done
FWS=aspnet $K/scripts/gt.sh
while read -r id; do [ -n "$id" ] && $K/scripts/run_g2.sh "$id"; done < $K/strict/g2_topologies.txt
while read -r id; do [ -n "$id" ] && $K/scripts/run_e4s.sh "$id"; done < $K/strict/e4_topologies.txt
echo PHASE2DONE
