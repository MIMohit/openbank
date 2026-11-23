#!/usr/bin/env bash
# W23 Task 3 validation, after the :pathmap images are built. ONE topology up at a time.
#   FRR: dbpm/dapm x {fastapi,express[,spring,aspnet]} x 6 scenarios, each with its scenario map.
#   E7 : dbpm/dapm x the nginx confirmed-witness sources -> hit counts vs the defence REPORT.
# Run from binding/harness.  Usage: task3_run.sh [fw ...]   (default: fastapi express)
set -uo pipefail
cd /Users/mimohit/openbank/binding/harness
G=../experiments/gaps/pathmap; S=$G/scripts; M=$G/maps
FWS="${*:-fastapi express}"
LOG=$G/task3_progress.log; : > $LOG
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a $LOG; }
log "TASK3 START fws=$FWS"

declare -A MAP=( [S0-identity]=identity.json [S1-strip-prefix]=S1-strip-prefix.json
                 [S2-version-rewrite]=S2-version-rewrite.json [S3-trailing-slash]=identity.json
                 [S4]=identity.json [S5-h2-to-h1]=identity.json )

log "FRR phase"
for cfg in dbpm dapm; do
  for fw in $FWS; do
    for scen in S0-identity S1-strip-prefix S2-version-rewrite S3-trailing-slash S4 S5-h2-to-h1; do
      $S/run_frr_pm.sh "$cfg" "$fw" "$scen" "$M/${MAP[$scen]}" >>$LOG 2>&1
      log "FRR $cfg $fw $scen -> $(cat $G/runs/frr/$cfg/w23-frrpm-$cfg-$fw-$scen/status.txt 2>/dev/null)"
    done
  done
done

log "E7 phase"
for cfg in dbpm dapm; do
  for fw in $FWS; do
    for ov in ovoff ovon; do
      src="ngx-$fw-$ov"
      $S/run_e7_pm.sh "$cfg" "$fw" "$src" >>$LOG 2>&1
      log "E7 $cfg $src -> $(cat $G/runs/e7/$cfg/w23-e7pm-$cfg-$src/status.txt 2>/dev/null)"
    done
  done
done
log "TASK3 DONE"
