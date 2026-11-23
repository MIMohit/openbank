#!/usr/bin/env bash
# Rerun one topology's full A_client battery N times, each on a FRESHLY started topology
# (orchestrator up->battery->down per rep), then report whether each violation vector is
# stable across reps (oracle_spec §10: confirmed = hit in all reps). Writes reruns/<id>/.
# Usage (from binding/harness): rerun_e4.sh <topology-id> [N]
set -uo pipefail
id=$1; N=${2:-3}
E4=$(cd ../experiments/e4 && pwd)
RR="$E4/reruns/$id"; rm -rf "$RR"; mkdir -p "$RR"
runner=run_one.sh; [[ "$id" == *laravel* ]] && runner=run_one_hcfix.sh
for r in $(seq 1 "$N"); do
  bash "../experiments/e4/scripts/$runner" "$id" "$RR/rep$r" >/dev/null 2>&1
  # pull the vector set that violated in this rep
  python3 - "$RR/rep$r/$id/violations.jsonl" > "$RR/rep$r.vectors" 2>/dev/null <<'PY'
import json,sys
try:
    vs=sorted({json.loads(l)["vector_id"] for l in open(sys.argv[1])})
except FileNotFoundError:
    vs=[]
print("\n".join(vs))
PY
  echo "rep$r: $(tr '\n' ' ' < "$RR/rep$r.vectors")"
done
# consistency: intersection and union across reps
python3 - "$RR" "$N" "$id" <<'PY'
import sys,os,json
rr,N,tid=sys.argv[1],int(sys.argv[2]),sys.argv[3]
sets=[]
for r in range(1,N+1):
    f=os.path.join(rr,f"rep{r}.vectors")
    sets.append(set(x.strip() for x in open(f) if x.strip()) if os.path.exists(f) else set())
union=set().union(*sets) if sets else set()
inter=set.intersection(*sets) if sets and all(sets) else (sets[0] if sets else set())
# per-vector count
cnt={v:sum(v in s for s in sets) for v in union}
confirmed=sorted(v for v,c in cnt.items() if c==N)
flaky=sorted(v for v,c in cnt.items() if 0<c<N)
out={"topology":tid,"reps":N,"confirmed":confirmed,"flaky":flaky,
     "per_vector_counts":cnt,"n_confirmed":len(confirmed),"n_flaky":len(flaky)}
json.dump(out,open(os.path.join(rr,"rerun_outcome.json"),"w"),indent=2,sort_keys=True)
print(json.dumps({"topology":tid,"n_confirmed":len(confirmed),"n_flaky":len(flaky),
                  "confirmed":confirmed,"flaky":flaky}))
PY
