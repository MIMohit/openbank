#!/usr/bin/env bash
# After phase 2: swap set (64 A1 topologies), legit FR (12), then 3x reruns (A1 variants whose hit sets are
# not identical to 'full' are rerun in full; identical variants are listed in REPORT), then G2 strict reruns.
cd /Users/mimohit/openbank/binding/harness
K=../experiments/ablation
until grep -q PHASE2DONE $K/phase2.log; do sleep 20; done
while read -r id; do [ -n "$id" ] && CASES=$K/cases_swap.jsonl $K/scripts/run_one.sh "$id" $K/runs_swap; done < $K/topologies.txt
echo SWAPDONE
while read -r id; do [ -n "$id" ] && $K/scripts/run_legit.sh "$id"; done < $K/legit/topologies.txt
echo LEGITDONE
grep -vE '^w18-(no-htm|no-ath)-' $K/topologies.txt > $K/reruns_list.txt
RL=$K/reruns_list.txt $K/scripts/rerun_all.sh a1 > $K/reruns_a1.log 2>&1
$K/scripts/rerun_all.sh g2 > $K/reruns_g2.log 2>&1
echo PHASE3DONE
