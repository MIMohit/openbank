#!/usr/bin/env bash
# W23 Task 1: 3x fresh reruns of swap / legit / E4-strict, plus the sorted QUERY_CANON attack-set runs.
# ONE topology up at a time, each rep up->run->down. Run from anywhere; it cd's to binding/harness.
set -uo pipefail
cd /Users/mimohit/openbank/binding/harness
G=../experiments/gaps
S=$G/scripts
LOG=$G/task1_progress.log
: > $LOG
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a $LOG; }

log "TASK1 START"

# ---- Phase Q: sorted QUERY_CANON on the attack set (1239 cases), 3 reps each of 8 topologies ----
log "PHASE Q (sorted attack) START"
for id in $(ls $G/topologies | grep '^w23-query-sorted-' | sed 's/\.yaml$//'); do
  for k in 1 2 3; do
    CASES=$G/cases.jsonl $S/run_one.sh "$id" "$G/sorted/rep$k" >>$LOG 2>&1
    log "Q $id rep$k $(tail -1 $G/sorted/rep$k/$id/status.txt 2>/dev/null)"
  done
done
log "PHASE Q DONE"

# ---- Phase S: swap set reruns (357 cases), 3 reps each of 16 topologies ----
log "PHASE S (swap) START"
for id in $(ls $G/topologies | grep -E '^w23-(no-htm|no-htu)-' | sed 's/\.yaml$//'); do
  for k in 1 2 3; do
    CASES=$G/cases_swap.jsonl $S/run_one.sh "$id" "$G/reruns/swap/rep$k" >>$LOG 2>&1
    log "S $id rep$k $(tail -1 $G/reruns/swap/rep$k/$id/status.txt 2>/dev/null)"
  done
done
log "PHASE S DONE"

# ---- Phase L: legit-traffic reruns, 3 reps each of 12 topologies ----
log "PHASE L (legit) START"
for id in $(ls $G/legit/topologies | sed 's/\.yaml$//'); do
  for k in 1 2 3; do
    $S/run_legit.sh "$id" >>$LOG 2>&1
    mkdir -p $G/reruns/legit/rep$k
    cp -R $G/legit/runs/$id $G/reruns/legit/rep$k/$id 2>/dev/null
    log "L $id rep$k $(tail -1 $G/legit/runs/$id/status.txt 2>/dev/null)"
  done
done
log "PHASE L DONE"

# ---- Phase E: E4-strict reruns, 3 reps each of 24 topologies ----
log "PHASE E (e4-strict) START"
for id in $(ls $G/strict/topologies | grep '^w23-e4-' | sed 's/\.yaml$//'); do
  for k in 1 2 3; do
    $S/run_e4s.sh "$id" "$G/reruns/e4/rep$k" >>$LOG 2>&1
    log "E $id rep$k $(tail -1 $G/reruns/e4/rep$k/$id/status.txt 2>/dev/null)"
  done
done
log "PHASE E DONE"

log "TASK1 ALL DONE"
