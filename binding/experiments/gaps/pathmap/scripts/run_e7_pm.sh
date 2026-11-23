#!/usr/bin/env bash
# W23 E7 under the path map: replay a confirmed A_leak witness set under dbpm/dapm (identity map,
# NO rewrite) and compare the surviving-hit count to the defence REPORT's D-B/D-A columns. Security
# is "unchanged" iff the hit set equals that of D-B (dbpm) / D-A (dapm). Run from binding/harness.
# Usage: run_e7_pm.sh <cfg:dbpm|dapm|db|da> <fw> <source>   (source = a defence/cases/<source>.jsonl stem)
set -uo pipefail
cfg=$1; fw=$2; src=$3
G=../experiments/gaps/pathmap; D=$(cd ../experiments/defence && pwd); S=$D/scripts
PY=orchestrator/.venv/bin/python
id=w23-e7pm-$cfg-$src
port=$(( 29600 + $(echo "$cfg-$src" | cksum | cut -d' ' -f1) % 180 ))
Y=$G/topos/$id.yaml; out=$G/runs/e7/$cfg/$id
mkdir -p $G/topos "$out"; rm -rf "$out"; mkdir -p "$out"
ov=$(echo "$src" | grep -q ovon && echo on || echo off)
python3 $G/scripts/make_pm_topo.py "$cfg" "$fw" "$id" "$port" > "$Y"
# override is read from the YAML by the runner; set it to match the source
sed -i '' "s/^override: .*/override: '$ov'/" "$Y"
export BH_PROJECT_PREFIX=w23-bh-; proj=w23-bh-$id; t0=$(date +%s)
if ! $PY -m orchestrator.up $Y --stubs off --fresh-logs --timeout 300 > "$out/up.log" 2>&1; then
  echo "UP FAILED $id" | tee "$out/status.txt"; $PY -m orchestrator.down $Y >/dev/null 2>&1; rm -rf orchestrator/generated/$id; exit 1; fi
docker compose -p $proj images --format json > "$out/images.json" 2>/dev/null || true
$PY $S/ext_run_matrix.py --topology $Y --cases $D/cases/$src.jsonl --out logs/$id/runner.jsonl > "$out/runner.stderr.log" 2>&1; rc=$?
docker compose -p $proj logs --no-color --tail 400 gateway > "$out/gateway.log" 2>&1 || true
$PY -m orchestrator.down $Y > "$out/down.log" 2>&1
cp logs/$id/*.jsonl "$out/" 2>/dev/null || true
mkdir -p "$out/generated" && cp -R orchestrator/generated/$id/. "$out/generated/" 2>/dev/null; rm -rf orchestrator/generated/$id
$PY -m oracle.correlate --log-dir "$out" --topology $Y --ground-truth $D/groundtruth/$fw-ov$ov.jsonl > "$out/correlate.log" 2>&1
n=$(wc -l < "$out/hits.jsonl" 2>/dev/null | tr -d ' ')
echo "$cfg $src hits=${n:-NA} rc=$rc secs=$(( $(date +%s)-t0 ))" | tee "$out/status.txt"
