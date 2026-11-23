# experiments/ablation (W18): A1 binding-claim ablation, A4 primitive-family leave-one-out, A5 gateway profiles

Results and interpretation: `REPORT.md`. This file covers what is here, how to run it, and its limits.

## Components
| path | what |
|---|---|
| `verifier_ablate/` | copy of `harness/verifier` (unchanged logic in `full`) + `bind.py` (env `BIND_CLAIMS`, `QUERY_CANON`) + `digest_gate.py` (RFC 9530 body check hop). Built as `bh-verifier:ablate`; thin variant tags `bh-verifier:ablate-<variant>` only set env (`scripts/build_images.sh`). |
| `minter_ablate/` | copy of `harness/minter` + `dpop.mint_bound()` (htu with query for `+query`; claim `cdig` = Content-Digest for `+digest`). |
| `cases.jsonl` | 1,239 kill-style depth-1 A_leak cases: all 17 base ops (13 v1 + 4 v2) x (84 W7 primitives + 2 W15 `x-frag-*`), + 17 baselines (`scripts/gen_cases.py`). |
| `cases_swap.jsonl` | 357 replay cases: leaked proof of op p sent on op q's canonical request (272) or with another method (68), + 17 baselines (`scripts/gen_swap_cases.py`). |
| `topologies/`, `topologies.txt` | 64 = 8 variants x nginx default edge x {fastapi,spring,rails,laravel} (`:v2`) x override {off,on}. |
| `groundtruth/` | op(pi) for all 17 ops, direct to each `:v2` executor (`scripts/gt.sh`), 0 nonconformant. |
| `runs/`, `runs_swap/` | A1 raw logs per topology (runner/verifier/executor/digest_gate jsonl, generated compose + gateway conf, hits.jsonl, summary.csv). |
| `legit/` | legit-traffic false-rejection runs (nginx default; HAProxy recommended + `query-sort-by-name`). |
| `strict/` | A5 new runs: G2 case set (176) x 5 gateways x {fastapi,aspnet,spring} x {strict, default, recommended}; E4 battery x 6 gateways x {aspnet,spring} x strict x {allow,block} PDP. |
| `reruns/`, `strict/reruns/` | 3x determinism reruns (fresh topology per rep) + `rerun_outcome.jsonl`. |
| `ddmin/` | minimised requests for 17 representative hits (`ddmin_selection.txt`; all still hit). `skew_reps.txt` / `reruns_skewfix.log`: 8 clock-skewed rerun reps, re-run. |
| `analysis/` | every table in REPORT.md (CSV/JSON), produced by `scripts/a1_analyse.py`, `scripts/a4_a5.py`. |

## How to run (from `binding/harness`; one topology at a time; projects `w18-bh-*`, containers `w18-*`)
```sh
PY=orchestrator/.venv/bin/python; A=../experiments/ablation
$A/scripts/build_images.sh
$PY $A/scripts/gen_cases.py --out $A/cases.jsonl; $PY $A/scripts/gen_swap_cases.py --out $A/cases_swap.jsonl
python3 $A/scripts/make_topologies.py; $PY $A/scripts/make_strict.py
$A/scripts/gt.sh; FWS=aspnet $A/scripts/gt.sh
$A/scripts/run_all.sh                                  # A1 (64)
$A/scripts/run_phase2.sh; $A/scripts/run_phase3.sh     # strict G2 + E4, swap, legit, reruns
cd $A && $PY scripts/a1_analyse.py && $PY scripts/a1_analyse.py runs_swap && $PY scripts/a4_a5.py --new
```
Tests of the verifier copy: `pytest verifier_ablate/tests` with `verifier`/`minter` importable as the ablation copies
(130 passed incl. the 124 original verifier tests in `full` mode + 6 `test_bind.py`; the original `test_cli` needs the
harness directory layout and was deselected).

## How the digest gate is inserted
`orchestrator.up --stubs off` starts the normal topology; `run_one.sh` then starts `w18-dg-<id>` (image
`bh-verifier:ablate`, `python -m verifier.digest_gate`) on the topology network with alias `digestgate`, rewrites the
generated `nginx.conf` in place (`proxy_pass http://executor:8080` -> `http://digestgate:8081`; the
`auth_request` location is untouched) and reloads nginx. The orchestrator itself is not modified.

## Known limitations
- `cdig` is an experimental, unregistered proof claim (RFC 9449 allows extra claims); there is no standard DPoP body binding.
- `+digest` needs a body-seeing hop: nginx `auth_request` sends the subrequest with `proxy_pass_request_body off`, so the
  edge verifier can only bind the Content-Digest header. Without the gate (`digest-nogate`) body binding buys nothing.
- A_leak with one token: the leaked proof is always replayed with its own access token, so `no-ath` cannot differ from
  `full` here (ath matters when a proof is paired with a different token of the same key).
- Single gateway (nginx default) for A1; route space is the synthetic bench API v1+v2.
- A4/A5 for default/recommended use existing W9/W13/W14/W15/W12 data; their raw hits are pooled as recorded there.
