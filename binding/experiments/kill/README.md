# experiments/kill: the kill experiment, decision gate G1 (W9)

**What it is.** 48 real topologies: {nginx, traefik, envoy} × {default, recommended} × edge × {fastapi, express, spring, aspnet} × override {off, on}.
Each received the exhaustive depth-1 case set (948 cases), was correlated by the W7 oracle, and every hit was re-run 3×. The verdict is in `G1_REPORT.md`.

| file / dir | content |
|---|---|
| `DESIGN.md` | matrix, pipeline, classification rule |
| `G1_REPORT.md` | gate verdict, tables, skepticism list |
| `ROOT_CAUSES.md` | per-root-cause notes (gateway step × framework step, version facts, sanity checks) |
| `FINDINGS.csv` | candidate disclosures + informational findings (no vendor contacted) |
| `topologies/`, `topologies.txt` | the 48 YAMLs (W6 `make_matrix.topo()` output, id prefixed `w9-`, ports 28100–28147) |
| `groundtruth/<fw>-ov<x>.jsonl` | op(π) per framework × override (runner `--direct`); `raw/` holds the direct logs, including the full depth-1 matrix sent straight to each executor (`*.all.jsonl`) |
| `runs/<id>/` | runner/verifier/executor logs, the generated compose and gateway config, gateway log, `hits.jsonl`, `propagation.jsonl`, `oracle_other.jsonl`; `runs/summary.csv` |
| `reruns/<id>/rep{1,2,3}/`, `rerun_outcome.jsonl` | 3× determinism reruns of every hit (`*.iat_skew_discarded` = reps invalidated by Docker clock skew, kept for the record) |
| `ddmin/` | per-root-cause minimised requests |
| `analysis/` | `signatures.csv`, `hits_per_topology.csv`, `pivot_gw_fw.csv`, `resolution.csv`, `outcomes_by_primitive.csv`, `hits_all.jsonl` |
| `scripts/` | `make_topologies.py`, `groundtruth.sh`, `run_one.sh`, `rerun.py`, `ddmin_hit.py`, `analyse.py`, `outcomes.py`, `probe_fragment.py` |

## How to reproduce
```sh
cd binding/harness
PY=orchestrator/.venv/bin/python
$PY ../experiments/kill/scripts/make_topologies.py
../experiments/kill/scripts/groundtruth.sh
cat ../experiments/kill/topologies.txt | xargs -P 2 -n 1 ../experiments/kill/scripts/run_one.sh
cat ../experiments/kill/topologies.txt | xargs -P 2 -n 1 $PY ../experiments/kill/scripts/rerun.py
cd ../experiments/kill && python3 scripts/analyse.py && python3 scripts/outcomes.py
```
Compose projects are `w9-bh-<id>` (`BH_PROJECT_PREFIX=w9-bh-`), ground-truth containers are `w9-gt-*`, and everything is torn down by the scripts.
`orchestrator.up` writes `harness/logs/w9-*/` and `harness/orchestrator/generated/w9-*/` as a side effect. The scripts copy both into this
directory and delete `generated/w9-*`. `harness/logs/w9-*` stay as the tool's scratch output. I did not edit `orchestrator/`, so no patch was needed.

## Known limitations
- Depth-1 only, one client (alice), and edge placement only.
- The bench API route space is sparse. It has no POST route that shares a path with another method, no nested GET routes and no catch-all path
  parameter. So POST-only method override and the dot-segment differential could not produce an op change (G1_REPORT §6).
- Docker-VM clock skew after host sleep invalidated some rerun reps (verifier `iat_skew`). Those reps were redone after a clock check (`rerun.py --redo-skewed`).
