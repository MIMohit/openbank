#!/usr/bin/env bash
# ddmin one representative case per distinct root cause, each on a freshly-upped topology.
# Run from binding/harness. ONE topology up at a time, w13-bh- prefix.
set -uo pipefail
K=../experiments/ext-gw
PY=orchestrator/.venv/bin/python
export BH_PROJECT_PREFIX=w13-bh-
log=$K/ddmin/ddmin.log; : > "$log"
run() {  # <topology> <case_id...>
  local tid=$1; shift
  local Y=$K/topologies/$tid.yaml
  echo "=== UP $tid ===" | tee -a "$log"
  $PY -m orchestrator.down "$Y" >>"$log" 2>&1
  if ! $PY -m orchestrator.up "$Y" --stubs off --fresh-logs --timeout 300 >>"$log" 2>&1; then
    echo "UP FAILED $tid" | tee -a "$log"; $PY -m orchestrator.down "$Y" >>"$log" 2>&1; return 1; fi
  $PY $K/scripts/ddmin_hit.py "$tid" "$@" 2>&1 | tee -a "$log"
  $PY -m orchestrator.down "$Y" >>"$log" 2>&1
  rm -rf orchestrator/generated/$tid 2>/dev/null
}
# G2 new class: APISIX %2f (resource) + G1 reps on same apisix topology
run w13-apisix-default-edge-aspnet-ovoff \
  deleteAccount:g2-pct2f-before-last:alice:bf8b98fbd922 \
  accountAction.freeze:g1-op-freeze-to-close:alice:b4ba45197e11 \
  graphql.getProfile:g1-gql-to-deleteProfile:alice:87f436958aca
# G2 fragment dispatch (apisix fastapi)
run w13-apisix-default-edge-fastapi-ovoff \
  accountAction.freeze:g2-fragment:alice:8c66fa6aaefa
# G2 fragment resource (kong fastapi)
run w13-kong-default-edge-fastapi-ovoff \
  adminDeleteUser:g2-fragment:alice:01108de983fd
# G1 method-override header (ovon)
run w13-kong-default-edge-fastapi-ovon \
  deleteAccount:g1-hdr-xhmo-get:alice:9fc762b8f583
echo "DDMIN ALL DONE" | tee -a "$log"
