#!/usr/bin/env bash
# Phase 3: after phase2 (a3host) finishes, ddmin-minimise one representative hit per distinct
# root cause, against a live topology (one up at a time). Writes ext-fw/ddmin/*.json.
set -uo pipefail
K=$(cd "$(dirname "$0")/.." && pwd)
HARNESS=$(cd "$K/../.." && pwd)/harness
PY=$HARNESS/orchestrator/.venv/bin/python
LOG=$K/ddmin/_driver.log
mkdir -p "$K/ddmin"
export BH_PROJECT_PREFIX=w14-bh-
for _ in $(seq 1 720); do
  grep -q 'phase2 a3host DONE' "$K/runs_a3host/_driver.log" 2>/dev/null && break
  sleep 15
done
echo "=== phase3 ddmin start $(date -u +%FT%TZ) ===" | tee -a "$LOG"

run_topo () {
  local tid=$1; shift
  local yml=$K/topologies/$tid.yaml
  echo "--- up $tid $(date -u +%FT%TZ) ---" | tee -a "$LOG"
  (cd "$HARNESS" && "$PY" "$K/scripts/up_hostfix.py" "$yml" --timeout 300) >> "$LOG" 2>&1
  if [ $? -ne 0 ]; then echo "UP FAILED $tid" | tee -a "$LOG"; (cd "$HARNESS" && "$PY" -m orchestrator.down "$yml") >>"$LOG" 2>&1; return; fi
  (cd "$HARNESS" && "$PY" "$K/scripts/ddmin_hit.py" "$tid" "$@") >> "$LOG" 2>&1
  (cd "$HARNESS" && "$PY" -m orchestrator.down "$yml") >> "$LOG" 2>&1
  rm -rf "$HARNESS/orchestrator/generated/$tid" 2>/dev/null || true
  echo "    done $tid $(date -u +%FT%TZ)" | tee -a "$LOG"
}

# RC1 query dispatch, RC2 body dispatch, RC4 form _method body-replace, RC7 fragment-in-query, RC6 fragment-resource
run_topo w14-nginx-default-edge-go-chi-ovoff \
  accountAction.freeze:g1-op-freeze-to-close:alice:b4ba45197e11 \
  graphql.getProfile:g1-gql-to-deleteProfile:alice:87f436958aca \
  graphql.getProfile:g1-fmethod-get:alice:a4d4d59a7629 \
  accountAction.freeze:g2-fragment:alice:8c66fa6aaefa \
  getAccount:g2-fragment:alice:3821accb50a4
# RC3 content-type relabel (go-chi, override on)
run_topo w14-nginx-default-edge-go-chi-ovon \
  graphql.getProfile:g1-ct-urlencoded:alice:45765f710853
# RC6 fragment-resource, cross-framework (laravel / FrankenPHP)
run_topo w14-nginx-default-edge-laravel-ovoff \
  getAccount:g2-fragment:alice:3821accb50a4
# RC5 header method-override, any method (fastapi Flask-pattern), origin placement
run_topo w14-envoy-default-origin-fastapi-ovon \
  getAccount:g1-hdr-xhmo-delete:alice:06f5703c3425

echo "=== phase3 ddmin DONE $(date -u +%FT%TZ) ===" | tee -a "$LOG"
