#!/usr/bin/env bash
# 3x determinism reruns (oracle_spec section 10): for every topology with hits, hit cases + baselines,
# each rep on a FRESH topology (run_one.sh / run_g2.sh do up --fresh-logs ... down). Run from binding/harness.
# Usage: rerun_all.sh a1|g2
set -uo pipefail
K=$(cd ../experiments/ablation && pwd); kind=$1
if [ $kind = a1 ]; then RUNS=$K/runs; L=${RL:-$K/topologies.txt}; ONE=$K/scripts/run_one.sh; ALL=$K/cases.jsonl; RR=$K/reruns
else RUNS=$K/strict/runs; L=$K/strict/g2_topologies.txt; ONE=$K/scripts/run_g2.sh; ALL=$K/strict/cases_g2.jsonl; RR=$K/strict/reruns; fi
mkdir -p $RR/cases
while read -r id; do
  [ -s $RUNS/$id/hits.jsonl ] || continue
  python3 - "$RUNS/$id/hits.jsonl" "$ALL" > $RR/cases/$id.jsonl <<'PY'
import json,sys
want={json.loads(l)["case_id"] for l in open(sys.argv[1])}
for l in open(sys.argv[2]):
    c=json.loads(l)
    if c["case_id"] in want or c.get("depth",0)==0: sys.stdout.write(l)
PY
  for k in 1 2 3; do CASES=$RR/cases/$id.jsonl $ONE $id $RR/rep$k > /dev/null 2>&1; echo "$id rep$k $(tail -c 120 $RR/rep$k/$id/status.txt)"; done
done < $L
echo RERUNDONE
