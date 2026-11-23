# experiments/defence: defence evaluation, E7 / E8 / A2 / performance / FRR (W17)

**What it is.** This directory re-runs every confirmed witness of the `kill`, `ext-routes`, `ext-gw` and `e4` experiments under the
three defences (D-A origin-routed, D-B view MAC, D-C strict edge) and four baselines (B-edge, B-origin, B-strict, B-optional). It
also runs a leave-one-out ablation of D-B's canonicalisation (A2), measures latency and throughput, and measures false rejection on
legitimate rewritten traffic. **Results: [`REPORT.md`](REPORT.md).**

## Layout
| path | content |
|---|---|
| `scripts/apply_db.py`, `scripts/build_defence.sh` | apply W11's D-B edits (imported from `harness/defence/patches/make_patches.py`) to copies of the current executors, build `bh-exec-<fw>:defence` |
| `build/src/executors/<fw>/`, `build/patches/*.v2.patch` | the patched copies (v2 routes + D-B) and the regenerated diffs |
| `build/verifier-optional/` | verifier copy with `BINDING_CHECKS=off` (B-optional), built as `bh-verifier:w17-optional` |
| `build/defence-tests/`, `results/unit/`, `scripts/run_e2e.sh`, `results/e2e/` | step 1: unit tests and e2e on the new images |
| `scripts/build_casesets.py`, `cases/` | the 11 A_leak witness sets (confirmed hits + baselines) with class/provenance metadata |
| `scripts/groundtruth.sh`, `groundtruth/` | op(π) on the `:v2` images (17 base ops × 8 framework/override pairs) |
| `scripts/make_topologies.py`, `topologies/<cfg>/`, `worklist_*.txt` | 77 A_leak + 41 E4 topologies (7 configs) |
| `scripts/run_one.sh`, `scripts/sweep.sh`, `runs/<cfg>/<id>/` | one run = up (`--stubs off`) → replay → down → oracle; raw logs, generated compose and gateway config |
| `runs_rep2/`, `scripts/phase3.sh`, `scripts/rep2_compare.py` | replication 2 of the whole E7/E4 sweep (118/118 identical) |
| `runs_invalid/` | the first D-A sweep, invalidated by the nginx/Kong Host rewrite (REPORT §9.1), kept for the record |
| `cases/full-v2-depth1.jsonl`, `topologies/e8full/`, `runs/e8full/` | E8 B-optional vs B-edge on the full 581-case corpus |
| `scripts/frr_client.py`, `scripts/frr_nginx.py`, `scripts/run_frr.sh`, `runs/frr/` | false-rejection measurement |
| `perf/load.js`, `scripts/run_perf.sh`, `scripts/perf_csv.py`, `results/perf/raw/` | k6 load runs; per-request latencies as `.lat.npy` (float32 ms), k6 summaries and logs; `scripts/phase2b.sh` (resumed perf under `caffeinate`), `scripts/diag_perf.sh` + `scripts/phase4.sh` → `results/perf/diag/` (status-code diagnostic); `runs_invalid/perf_sleep_token_expiry/` (invalidated run) |
| `scripts/analyse.py`, `a2_ablation.py`, `frr_analyse.py`, `perf_analyse.py`, `analysis/` | every table in REPORT.md (`*.md`) and its long-form data (`*.csv`) |

## How to run (from `binding/harness`; ONE topology at a time)
```sh
PY=orchestrator/.venv/bin/python; X=../experiments/defence
python3 $X/scripts/apply_db.py && $X/scripts/build_defence.sh
docker build -t bh-verifier:w17-optional -f $X/build/verifier-optional/Dockerfile $X/build/verifier-optional
for fw in fastapi express spring aspnet; do $X/scripts/run_e2e.sh $fw; done
python3 $X/scripts/build_casesets.py && $X/scripts/groundtruth.sh && $PY $X/scripts/make_topologies.py
$X/scripts/sweep.sh $X/worklist_aleak.txt aleak; $X/scripts/sweep.sh $X/worklist_e4.txt e4
for cfg in bedge borigin bstrict da db dc; do for fw in fastapi express spring aspnet; do $X/scripts/run_frr.sh $cfg $fw; done; done
for fw in fastapi spring; do for cfg in bedge borigin da db; do $X/scripts/run_perf.sh $cfg $fw 5 60s; done; done
cd $X && python3 scripts/analyse.py && python3 scripts/a2_ablation.py && \
  build/.venv-stats/bin/python scripts/frr_analyse.py && build/.venv-stats/bin/python scripts/perf_analyse.py && python3 scripts/rep2_compare.py
```
`build/.venv-stats` is a Python 3.12 venv with numpy 2.3.3 and scipy 1.16.2. It imports `/Users/mimohit/openbank/analysis/stats.py`.

## How to test
Step 1 is the test of the built artefacts: unit tests (Python 75, Node 38, Java 76, C# 76) and the 7-case e2e, identical to W11.
Each sweep run also replays the depth-0 baselines, and the A2 offline model is validated against the live D-B runs (472/472).

## Known limitations
See REPORT.md §9: the Host work-around for origin placement, env baked into images, FRR rewrites injected into the generated
nginx.conf (nginx only), the witness-set design, offline A2, and laptop-grade timing (perf is preliminary).
Nothing under `harness/` was modified. No git commits were made.
