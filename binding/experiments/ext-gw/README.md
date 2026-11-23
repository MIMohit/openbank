# experiments/ext-gw (W13): remaining gateways — kong, apisix, haproxy

Re-runs the kill-experiment methodology (A_leak, depth-1, binding oracle) on the three gateways
not covered by `kill/`, across default+recommended profiles, placement=edge, all 8 frameworks,
override off/on = **96 topologies**. Owner: W13. Tag/prefix: `w13-bh-`.

## Layout
- `topologies/*.yaml` — 96 topology specs (gateway images pinned in each).
- `runs/<id>/` — per-topology logs + `hits.jsonl` (oracle output). All 96 present.
- `analysis/` — regenerate with `harness/orchestrator/.venv/bin/python scripts/analyse.py`
  (run from `harness/`). `hits_all.jsonl`, `hits_per_topology.csv`, `signatures.csv`,
  `resolution.csv`, `pivot_gw_fw.csv`.  **NB:** always regenerate after all runs finish — an
  earlier aggregate that predated the laravel runs silently dropped them.
- `reruns/<id>/` — determinism reruns, every hit case 3× on a fresh topology
  (`scripts/rerun.py <id> --reps 3`). Default-profile topologies only (default==recommended,
  byte-identical). `rerun_outcome.jsonl`: confirmed/flaky/irreproducible. All 684 hit cases confirmed.
- `ddmin/*.json` — minimal witness per distinct root cause (`scripts/ddmin_hit.py`, live topology).
- `notes/root_causes.md` — config evidence + root-cause reasoning + skepticism.
- `REPORT.md`, `FINDINGS.csv` — deliverables (format = `kill/G1_REPORT.md`).

## How to reproduce one topology
From `binding/harness`:  `bash ../experiments/ext-gw/scripts/run_one.sh <topology-id>`
(BH_PROJECT_PREFIX=w13-bh-, one topology up at a time, `--stubs off`).

## Headline
1368 hits (g1 1188, g2 180, g3 0); genuine G2 after ddmin = 168. 1 new independent G2 class:
**RC-W13-A**, the APISIX forward-auth decoded-view / raw-`%2f`-upstream split. default==recommended
everywhere; haproxy has zero G2. See REPORT.md.

## Known limitations
- Single client (alice), edge placement only, depth-1, 948-case route space (same as kill).
- 2/91008 cases hit a transient transport error (status 0), both non-hit cases.
- APISIX forward-auth has a startup race (route-plugin applies shortly after container health);
  one rerun rep bypassed once (b0) and was re-run — reps 2/3 and the re-run were deterministic.
