#!/usr/bin/env bash
# Safety guard (runs ON the server, from /root/bhperf). Every 15 s (spec: <= 30 s) it reads /proc/loadavg,
# MemAvailable and swap from /proc/meminfo, and the status of every production container (all containers
# that existed before the experiment, i.e. names not starting with bhperf-; read-only `docker ps`).
# ABORT if MemAvailable < 900 MiB, 1-min load > 1.6, a production container is not Up, or swap used grows
# > 300 MiB over the value at guard start. On abort it force-removes ONLY containers that carry BOTH the
# label bhperf=1 AND a name starting with bhperf-, then writes /root/bhperf/ABORT (the runner checks it).
# It also self-terminates (with the same cleanup) after MAX_S seconds, and stops on /root/bhperf/GUARD_STOP.
# Usage: guard.sh check   -> one check, exit 0 ok / 1 violation (prints the line)
#        guard.sh loop    -> background loop (start with: setsid nohup ./guard.sh loop >/dev/null 2>&1 &)
R=/root/bhperf; LOG=$R/guard.log; MAX_S=${MAX_S:-10800}; IV=${IV:-15}
PROD_FILE=$R/prod_containers.txt; SWAP0_FILE=$R/swap0_kib.txt
[ -s $PROD_FILE ] || docker ps --format '{{.Names}}' | grep -v '^bhperf-' > $PROD_FILE
swap_used() { awk '/^SwapTotal:/{t=$2}/^SwapFree:/{f=$2}END{print t-f}' /proc/meminfo; }
[ -s $SWAP0_FILE ] || swap_used > $SWAP0_FILE

cleanup() {
  for id in $(docker ps -aq --filter label=bhperf=1); do
    n=$(docker inspect -f '{{.Name}}' $id | sed 's#^/##')
    case $n in bhperf-*) docker rm -f $id >/dev/null 2>&1 && echo "$(date -u +%FT%TZ) removed $n" >> $LOG;; esac
  done
}

check() {
  local l1 ma sw sw0 dsw st bad="" n
  l1=$(cut -d' ' -f1 /proc/loadavg)
  ma=$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo)
  sw=$(swap_used); sw0=$(cat $SWAP0_FILE); dsw=$(( (sw - sw0) / 1024 ))
  for n in $(cat $PROD_FILE); do
    st=$(docker ps --filter "name=^${n}\$" --format '{{.Status}}')
    case $st in Up*) ;; *) bad="$bad prod_down:$n";; esac
  done
  [ "$ma" -lt 900 ] && bad="$bad memavail<900MiB"
  awk -v l=$l1 'BEGIN{exit !(l>1.6)}' && bad="$bad load1>1.6"
  [ "$dsw" -gt 300 ] && bad="$bad swap+${dsw}MiB>300"
  nb=$(docker ps -q --filter label=bhperf=1 | wc -l)
  line="$(date -u +%FT%TZ) load1=$l1 memavail_mib=$ma swap_delta_mib=$dsw prod_up=$(( $(wc -l < $PROD_FILE) - $(echo $bad | grep -o prod_down | wc -l) ))/$(wc -l < $PROD_FILE) bhperf_running=$nb"
  if [ -n "$bad" ]; then echo "$line VIOLATION:$bad"; return 1; fi
  echo "$line ok"; return 0
}

case ${1:-check} in
  check) check | tee -a $LOG; exit ${PIPESTATUS[0]} ;;
  loop)
    echo $$ > $R/guard.pid; t0=$(date +%s)
    echo "$(date -u +%FT%TZ) guard start pid=$$ swap0_kib=$(cat $SWAP0_FILE) prod=$(tr '\n' ' ' < $PROD_FILE)" >> $LOG
    while :; do
      [ -e $R/GUARD_STOP ] && { echo "$(date -u +%FT%TZ) guard stop (GUARD_STOP)" >> $LOG; rm -f $R/guard.pid; exit 0; }
      if ! out=$(check); then
        echo "$out" >> $LOG; echo "$out" >> $R/ABORT
        echo "$(date -u +%FT%TZ) ABORT -> removing bhperf containers" >> $LOG; cleanup
      else echo "$out" >> $LOG; fi
      if [ $(( $(date +%s) - t0 )) -gt $MAX_S ]; then
        echo "$(date -u +%FT%TZ) guard max lifetime reached -> cleanup" >> $LOG; echo "max lifetime" >> $R/ABORT; cleanup; rm -f $R/guard.pid; exit 0
      fi
      sleep $IV
    done ;;
esac
