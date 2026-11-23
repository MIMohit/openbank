#!/usr/bin/env bash
# Run the A_client spec against the gitea PDP stack once per policy file.
# Relaunches ONLY the verifier(=PDP) container with a new POLICY_FILE between policies
# (app + gateway stay up; one topology at a time). Usage: run_aclient_policies.sh <app_dir> <spec> <outdir> <policy...>
set -u
APPDIR=$1; SPEC=$2; OUT=$3; shift 3
RA=/Users/mimohit/openbank/binding/experiments/realapps
PY=/Users/mimohit/openbank/binding/harness/orchestrator/.venv/bin/python
cd "$APPDIR"
mkdir -p "$OUT"
for pol in "$@"; do
  echo "=== policy: $pol ==="
  : > logs/verifier.jsonl; rm -f logs/pdp.jsonl
  POLICY_FILE=/policies/$pol.json POLICY_NAME=$pol \
    docker compose -f docker-compose.pdp.yml up -d --force-recreate verifier >/dev/null 2>&1
  sleep 2; docker logs w22-gitea-pdp-verifier 2>&1 | tail -1
  PYTHONPATH=/Users/mimohit/openbank/binding/harness $PY "$RA/scripts/probe_lib.py" "$SPEC" "$OUT/aclient__$pol.jsonl"
  cp logs/pdp.jsonl "$OUT/pdp__$pol.jsonl" 2>/dev/null || true
done
