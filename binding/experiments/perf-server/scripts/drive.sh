#!/usr/bin/env bash
# Mac-side driver. For each topology: mint a fresh token+proof (1 h token lifetime; one topology takes ~17 min),
# copy it to the server, run server/run_topology.sh over ssh (blocking), copy the results back.
# Stops at the first abort / failure (no automatic retry). Usage: drive.sh "<names>" "<levels>" [runs] [dur]
set -uo pipefail
H=root@62.238.127.179; SSH="ssh -o BatchMode=yes -o ServerAliveInterval=20 -o ServerAliveCountMax=6"
X=$(cd "$(dirname "$0")/.." && pwd); HAR=$(cd $X/../../harness && pwd)
NAMES=$1; LEVELS=$2; RUNS=${3:-5}; DUR=${4:-60s}
mkdir -p $X/results/raw $X/results/tokens_local; chmod 700 $X/results/tokens_local
for name in $NAMES; do
  echo "== $name $(date -u +%FT%TZ)"
  (cd $HAR && orchestrator/.venv/bin/python -c "
import sys; sys.path.insert(0,'.')
from runner.minter_adapter import get_minter
a,p,j=get_minter(prefer='w3').mint(client='alice',htm='GET',htu='http://api.bench.test/api/v1/accounts/acc-alice-1')
print('AUTHZ=\"'+a+'\"'); print('PROOF=\"'+p+'\"')") > $X/results/tokens_local/$name.env
  $SSH $H "umask 077; cat > /root/bhperf/tokens/$name.env" < $X/results/tokens_local/$name.env
  $SSH $H "cd /root/bhperf && ./run_topology.sh $name '$LEVELS' $RUNS $DUR"; rc=$?
  mkdir -p $X/results/raw/$name
  rsync -a -e "$SSH" $H:/root/bhperf/results/$name/ $X/results/raw/$name/
  echo "== $name rc=$rc $(date -u +%FT%TZ)"
  [ $rc -eq 0 ] || { echo "STOP: $name rc=$rc"; exit $rc; }
done
rsync -a -e "$SSH" $H:/root/bhperf/guard.log $H:/root/bhperf/runner.log $X/results/
