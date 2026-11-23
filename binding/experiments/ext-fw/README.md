# ext-fw — W14: remaining frameworks + origin placement

Extension-round experiment (CONTRACT §12). Two parts:
- **(a)** framework breadth: {nginx, traefik, envoy} × {default, recommended} × placement=edge ×
  {django, go-chi, rails, laravel} × override {off, on} = 48 topologies, A_leak kill methodology.
- **(b)** A3 ablation: {nginx, envoy} × default × {origin, both} × all 8 frameworks × override on = 32 topologies.

**Read `REPORT.md` first** (format of `../kill/G1_REPORT.md`; has a dedicated §A3). Root-cause detail in
`notes/ROOT_CAUSES.md`; disclosure candidates in `FINDINGS.csv`.

## Headline
80 topologies, 75,840 requests, 0 transport errors, **694 hits** (all confirmed 3/3), 0 B0 bypass.
**Independent G2/G3 classes: 1** (the `#`-fragment differential, RC6/RC7 — W9's class, now extended to go-chi + laravel +
traefik). **G3 binding hits: 0.** Rails and Laravel decouple the executed method from the proof `htm` **by default**
(Laravel has no off switch; the W5 Rails app is non-API so ships `Rack::MethodOverride`), but it is G1 and cannot become a
hit in this route space (no non-POST route shares a POST path). A3: app-side `origin-raw` verification removes **neither** the
G1 dispatch/override **nor** the G2 fragment differential (clean on envoy-origin and Host-corrected nginx-origin); the 0-hits
seen for raw nginx-origin and for all `both` topologies are harness artefacts (nginx Host rewrite; shared one-time-jti replay).

## Layout
- `topologies/` — 80 topology YAMLs (`w14-…`).
- `runs/` — main run per topology: `{runner,verifier,executor,hits,propagation,oracle_other}.jsonl`, `summary.csv`, logs.
- `reruns/` — 3× determinism reruns (oracle_spec §10) for the 56 topologies with hits; `*/rerun_outcome.jsonl`.
- `runs_a3host/` — Host-corrected nginx-origin A3 runs (the §A3.2 artefact correction).
- `reruns_a3host/` — 3× reruns of the Host-corrected nginx-origin hits.
- `ddmin/` — per-root-cause request-delta minimisation (`*.json`, `still_hit:true`).
- `groundtruth/` — `op(π)` ground truth per framework × override (direct, no gateway, VERIFY_MODE=off).
- `analysis/` — `hits_all.jsonl`, `hits_per_topology.csv`, `signatures.csv`, `resolution.csv`, pivots, `outcomes_by_primitive.csv`.
- `notes/ROOT_CAUSES.md` — RC1–RC7 + L1, with framework/server version facts and citations.
- `scripts/` — see below.

## How to run / reproduce (from `binding/harness`, with its venv)
```sh
PY=orchestrator/.venv/bin/python
K=../experiments/ext-fw
# one topology, full 948-case matrix (uses up_hostfix: disables the flaky Laravel healthcheck,
# and for nginx origin/both preserves the public Host — see §A3.2):
bash $K/scripts/run_one_hostfix.sh w14-nginx-default-edge-go-chi-ovoff $K/runs
# aggregate:
$PY $K/scripts/analyse.py $K/topologies.txt      # analysis/*.csv, hits_all.jsonl
$PY $K/scripts/outcomes.py                        # analysis/outcomes_by_primitive.csv
# 3x determinism reruns for a topology that had hits:
$PY $K/scripts/rerun_hc.py w14-nginx-default-edge-go-chi-ovoff --reps 3
# ddmin one hit against a LIVE topology (bring it up first):
$PY $K/scripts/ddmin_hit.py <topology-id> <case-id> ...
```
Batch drivers: `run_reruns_all.sh <list>`, `run_phase2_a3host.sh`, `run_phase3_ddmin.sh`, `run_phase4_a3host_reruns.sh`.

## Scripts (W9 `kill/scripts` adapted; CONTRACT §12 "copy and adapt, do not edit kill/")
- `make_topologies.py` — emit the 80 topology YAMLs.
- `groundtruth.sh` — ground-truth each framework × override.
- `up_hostfix.py` / `up_hcfix.py` — §12 local work-arounds (orchestrator/ and gateways/ are W6-owned, untouched):
  disable the executor's inherited FrankenPHP/Caddy healthcheck (flaps `--wait`); `up_hostfix.py` also restores
  `proxy_set_header Host $host;` on the nginx **default** profile for origin/both so app-side verification is not
  degenerate (§A3.2). Both print the host port like `orchestrator.up`.
- `run_one.sh` / `run_one_hostfix.sh` — single-topology run + correlate.
- `rerun_hc.py` — reruns via `up_hostfix.py`; retries a rep whose verifier never engaged (cold-start ext_authz-open, a
  readiness failure treated like §10 `rerun_timing_deny`). `--runs-dir/--reruns-dir` select the A3-host set.
- `ddmin_hit.py` — request-delta ddmin against a live topology.
- `analyse.py`, `outcomes.py`, `probe_fragment.py`.

## Known limitations
- The method-override gap (RC5) for Rails/Laravel is real and default-on but produces no hit here because the bench API has
  no non-POST route sharing a POST path (the W9 §6 route-coverage gap). W15's v2 route space is where it would become a hit.
- `placement=both` cannot be measured for binding with the harness's single `JTI_CACHE=on` verifier (the origin leg always
  `jti_replay`); it would need `JTI_CACHE=off` on the origin leg or an edge-trusting origin (D-A/D-B, W11).
- Fragment G2 impact is low in this route space (suffix of the last path segment only; no reachable route/owner substitution).
