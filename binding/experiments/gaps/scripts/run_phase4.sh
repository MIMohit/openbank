#!/usr/bin/env bash
# After phase 3: ddmin the representative hits (ddmin_selection.txt), one topology up at a time.
cd /Users/mimohit/openbank/binding/harness
K=../experiments/ablation
until grep -q PHASE3DONE $K/phase3.log; do sleep 20; done
for y in $(awk '{print $1}' $K/ddmin_selection.txt | awk '!s[$0]++'); do
  line=$(grep -m1 "^$y " $K/ddmin_selection.txt); set -- $line
  ids=$(grep "^$y " $K/ddmin_selection.txt | awk '{print $6}' | tr '\n' ' ')
  $K/scripts/ddmin_run.sh $1 $2 $3 $4 $5 $ids
done
echo PHASE4DONE
