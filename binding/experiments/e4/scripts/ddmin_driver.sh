#!/usr/bin/env bash
# up a topology -> e4_ddmin the given vectors -> down. One at a time. Run from binding/harness.
set -uo pipefail
PY=orchestrator/.venv/bin/python
export BH_PROJECT_PREFIX=w12-bh-
run() {
  local id=$1; shift
  local Y=../experiments/e4/topologies/$id.yaml
  echo "=== DDMIN up $id ($(date +%H:%M:%S)) ==="
  if ! $PY -m orchestrator.up "$Y" --stubs off --fresh-logs --timeout 300 > /tmp/ddmin_up_$id.log 2>&1; then
    echo "UP FAILED $id"; tail -5 /tmp/ddmin_up_$id.log; $PY -m orchestrator.down "$Y" >/dev/null 2>&1; return 1
  fi
  $PY ../experiments/e4/scripts/e4_ddmin.py "$id" "$@"
  $PY -m orchestrator.down "$Y" > /dev/null 2>&1
  echo "=== DDMIN down $id ==="
}
run w12-block-ngx-aspnet-def dotseg-bob-get case-admin-list
run w12-block-ngx-spring-def matrix-accounts-bob
run w12-block-ngx-rails-def  dslash-accounts-bob
run w12-allow-kng-fastapi-def dotseg-bob-get
echo "DDMIN DRIVER done $(date +%H:%M:%S)"
