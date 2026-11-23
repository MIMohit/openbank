# Kill experiment (decision gate G1): design

Owner: W9. Directory: `binding/experiments/kill/`. Repo commit at start: `e7113b7`.

## Question
Does binding soundness fail in realistic layered deployments in a way that goes **beyond** what
RFC 9449 already concedes by design? Gate criterion (coordinator brief):

> at least 2 independent topology classes on current releases with binding resolution > 1 caused
> by G2 or G3, **OR** G1 reachable in default/common configurations of >= 2 major frameworks.

## Matrix (48 topologies)
| factor | levels |
|---|---|
| gateway | nginx 1.30.7-alpine, traefik v3.7.19, envoy v1.39.6 (pinned by W6, `gateways/README.md`) |
| profile | default, recommended (W6 definitions, `gateways/README.md`) |
| placement | edge (gateway calls the reference verifier through its CONTRACT §4 adapter) |
| framework | fastapi, express, spring, aspnet (`bh-exec-*:latest`, W4/W5) |
| override | off, on (executor `OVERRIDE`) |
| verifier | `bh-verifier:latest`, `HTU_CANON=rfc3986`, `JTI_CACHE=on`, `VIEW_MAC=off` |

The YAMLs in `topologies/` are produced by `scripts/make_topologies.py`, which calls W6's
`orchestrator.make_matrix.topo()` unchanged and then only (a) prefixes the id with `w9-` and
(b) assigns host ports 28100–28147. This keeps my `logs/<id>/`, `generated/<id>/`, compose projects
(`w9-bh-<id>`, via `BH_PROJECT_PREFIX`) and ports disjoint from other workers'. Nothing is
written to `orchestrator/topologies/`.

## Cases
Depth-1, exhaustive: every one of the 84 primitives (W7 catalogue) applied to every compatible base
op (13 base ops, CONTRACT §3), plus the 13 depth-0 baselines = **948 cases per topology**, client
`alice` (generated in-process by `mutator.compose.generate(depth=1)`; deterministic). Each case is sent
once as raw bytes with a freshly minted W3 token + proof bound to the base op's canonical (htm, htu).

## Ground truth (oracle_spec §2)
`scripts/groundtruth.sh`: for each framework × override, run the executor image alone
(`docker run`, `VERIFY_MODE=off`, container `w9-gt-<fw>-ov<x>`), send the 13 baselines with
`runner.run_matrix --direct`, build `groundtruth/<fw>-ov<x>.jsonl` with `runner.build_groundtruth`.
The same container additionally receives the **full** depth-1 matrix directly (`--direct-all`,
`groundtruth/raw/<fw>-ov<x>/{runner,executor}.all.jsonl`). That "framework-only map" says what the
framework executes for a mutated request with no gateway in front, which lets me attribute a hit to
the framework vs. the gateway.

## Per-topology pipeline (`scripts/run_one.sh <id>`)
1. `orchestrator.up <yaml> --stubs off --fresh-logs` (real images only; a missing image fails).
2. `runner.run_matrix --topology <yaml> --minter w3` (948 cases).
3. Save gateway logs, `orchestrator.down`.
4. Copy `harness/logs/<id>/*.jsonl` and `orchestrator/generated/<id>/` into `runs/<id>/`, then delete
   `generated/<id>/` (as W7 did).
5. `oracle.correlate` on `runs/<id>/` with the matching ground truth → `hits.jsonl`,
   `propagation.jsonl`, `oracle_other.jsonl`, one row in `runs/summary.csv`.

At most 2 topologies run at once (`xargs -P 2`).

## Analysis (`scripts/analyse.py`)
- Hit tables per gateway × framework × profile × override.
- **Root-cause signature** (cross-topology): `(primitive set, base op, executed op, deviation kinds)`.
  Each signature is attributed to a causing component using the topologies it occurs in and the
  framework-only map: it is gateway-level if presence depends on the gateway/profile, framework-level if it
  depends on framework/override, and verifier-level (by design) if it occurs everywhere the request
  reaches the executor unchanged.
- Resolution distribution: `max res_hat` per (topology, base op).

## Confirmation (`scripts/rerun.py`)
For each distinct root-cause signature, one representative (topology, case) per distinct topology class
is re-run **3×** on a freshly started topology (oracle_spec §10: down/up between reruns, new proof each
time). Depth-1 cases have one primitive, so primitive-level ddmin is trivial; `ddmin` from
`oracle/minimise.py` is applied at the level of the request delta (request-target characters and added header
lines relative to the canonical request) to get a minimal request.

## Manual checks
- `#fragment` resource hits (W7 flagged them pending review): check that the executor really ran the handler
  with the suffixed id and the response body echoes it, and what the verifier view was.
- Any hit with an unexpected status/body: check the executor log line and the runner's response body op_id agree.

## Classification rule
- **G1 (by design)**: the verifier's (htm, htu) view is identical to the canonical one and the
  operation change comes from a component RFC 9449 does not bind (query, body, override header/param).
  Expected; not evidence for the gate on its own except via the "≥ 2 major frameworks in default/common
  config" clause.
- **G2**: the verifier's view and the router's interpretation of method/path differ (the verifier
  accepted a view that maps to `op(π)`, but the router resolved the bytes to another op/resource).
- **G3**: an operation change driven by a spoofable trust/forwarding header.
