# Zero Trust Open Banking Testbed

A reproducible testbed measuring what a continuous, context-bound Zero Trust layer adds *on top of* a standards-correct FAPI 2.0 / DPoP baseline for Open Banking APIs.

## What this measures

Three configurations, evaluated against identical workloads and attacks:

| Config | Description |
|--------|-------------|
| **B0** | Weak baseline — plain OAuth 2.0 bearer, no DPoP, no policy |
| **B1** | FAPI 2.0 — PAR + PKCE + DPoP + short-lived tokens (standard checks only) |
| **P**  | B1 + Zero Trust Controller: device-binding, telemetry, risk scoring, OPA policy |

The key result is **P − B1**: what Zero Trust adds beyond a well-implemented standard.

## Prerequisites

- Docker + Docker Compose (recent version)
- Python ≥ 3.12 (for local unit tests)
- 8 GB RAM, any modern x86-64 or ARM64 machine

## Quick start

```bash
cp .env.example .env
make up        # starts Keycloak, OPA, Mock ADR API, ZT Controller
make test-unit # unit tests (no Docker needed)
make attacks   # run A1–A6 attack suite (organic detection — the primary numbers)
make analysis  # generate figures and tables
```

Full measurement run, in the order the paper reports it:

```bash
make attacks           # A1–A6 against B0 / B1 / P
make experiments       # legitimate workload + CPU/memory sampling, per config
make scaling           # latency and throughput at 5/10/20/40 concurrent users
make attacks-oracle    # detection-ceiling run (see "Oracle tag" below)
make attacks-adaptive  # A7, the adaptive adversary (see "Adaptive adversary" below)
make ablation          # P, P−device-binding, P−context, P−velocity, B1
make analysis          # every table and figure the manuscript cites
make verify-manuscript # fail if any number in the manuscript drifted from the data
```

The manuscript and its supporting material are in `paper/` — see `paper/README.md`.

## Architecture

```
Client Simulator
      │
      ▼
ZT Controller (port 9000)        ← FastAPI PEP+PDP reverse proxy
  1. token_verify (AT sig/exp/cnf.jkt)
  2. dpop_verify  (JWS, jti cache, ath, htu/htm)
  3. telemetry    (device fp, geo, velocity, rate)
  4. risk         (rule-based score → belief b_t)
  5. policy       (OPA: ALLOW / CHALLENGE / DENY)
  6. proxy        (forward to Mock ADR API)
      │
      ▼
Mock ADR API (internal only)     ← FastAPI resource server
  - Basiq-isomorphic endpoints
  - Object-level ownership enforcement
  - Synthetic data (seed=42, 100 users × 3 accounts × 200 tx)
      │
Keycloak (port 8080)             ← IdP (DPoP+PKCE+PAR realm)
OPA      (port 8181)             ← Policy engine (zt.rego)
```

## Mode switching (B0 / B1 / P / ablations)

Set `ZT_MODE` in `.env` or pass it to docker compose:

```bash
ZT_MODE=B1 docker compose up -d zt-controller
ZT_MODE=P  docker compose up -d zt-controller
```

Individual feature flags for ablations. Each maps to one enforcement
component, so an observed change is attributable to it:

| Flag | Removes |
|------|---------|
| `ZT_CHECK_DEVICE_BINDING=false` | the `cnf.jkt` binding check and risk rules R1/R2 |
| `ZT_ENABLE_TELEMETRY=false` | the telemetry PIP, and with it R3 (geo velocity), R5 (session continuity), R6 (DPoP-failure history) |
| `ZT_ENABLE_VELOCITY=false` | the call-rate rule R4 only |

```bash
ZT_MODE=P ZT_ENABLE_VELOCITY=false docker compose up -d zt-controller
```

Leave a flag unset (not empty-string, not `true`) to keep `ZT_MODE`'s own
coherent default for it. `make ablation` drives all five cells for you.

## Experiment matrix

| Experiment | Command | Outputs |
|------------|---------|---------|
| E1 Security (attacks) | `make attacks` | `table1_taxonomy.csv`, `fig2_attack_success_rate.png` |
| E2 False challenge / deny | `make experiments` | `table2_false_challenge.csv` |
| E3/E4 Performance | `make experiments` | `table3_latency.csv`, `table4_resource_overhead.csv`, `fig3_latency.png` |
| E4b Load scaling | `make scaling` | `table8_scaling.csv`, `fig4_scaling.png` |
| E5 Ablation | `make ablation` | `table5_ablation.csv`, `fig5_ablation.png` |
| Detection ceiling | `make attacks-oracle` | `table1b_oracle_ceiling.csv` |
| Adaptive adversary (A7) | `make attacks-adaptive` | `table9_adaptive_adversary.csv` |
| Analysis | `make analysis` | all of the above, plus `table6_threshold_sensitivity.csv`, `table7_risk_components.csv`, `table_effect_sizes.csv`, and the twelve manuscript figures in `paper/figures/` |

### Oracle tag — read this before interpreting any attack number

Risk rule R7 scores any request carrying `x-attack-context: true` at 0.90,
just under the 0.70 deny threshold. That header is sent by the attack
harness, so a run with it enabled measures what the enforcement pipeline
would block *given a perfect detector* — a detection ceiling — not what it
detects. It is **off by default**, in the controller
(`ZT_ORACLE_ATTACK_CONTEXT`) and in the suite (`attacks.runner --oracle-tag`),
and `make attacks` never enables it. `make attacks-oracle` is the ceiling run
and is reported separately in the paper. `data/tables/table7_risk_components.csv`
audits this: the `attack_context` column must read 0.0 on every primary row.

### Adaptive adversary — read this before quoting the A4 result

A4 measures an account takeover by an adversary who makes no attempt to evade
the contextual rules. Under P it succeeds 11 times in 30, and reading the raw
records shows those 11 are exactly the requests where the unknown-device
penalty (0.35) is the only rule firing, below the 0.40 challenge threshold; the
refusals either side come from two sliding-window transients. A7 is the same
takeover played by an adversary who paces below the rate rule and mimics the
victim's self-reported context — both granted by the threat model. It succeeds
30 times in 30 at the shipped operating point, and 0 times in 30 at
`ZT_RISK_THRESHOLD_ALLOW=0.3`. `make attacks-adaptive` runs all five cells.

A7 is not in the attack runner's default set, writes to
`data/raw/attacks_adaptive/` under its own run labels, and therefore cannot
perturb any primary number; every previously reported table regenerates
byte-identically with it present.

### Harness control plane

The controller exposes `POST /admin/reset-state` (guarded by the internal
service secret) which drops telemetry history, the per-subject device-key
registry and the DPoP `jti` cache. The attack runner calls it before each
attack so that, for example, A6's call-rate signal does not inherit A3's
burst. It is not part of the measured data path.

## Reproducibility

- All random seeds fixed (`GLOBAL_SEED=42`, `MOCK_ADR_SEED=42`)
- Docker images pinned by version tag (see `docker-compose.yml`)
- Python dependencies pinned in `requirements.txt` files
- JSONL output in `data/raw/` is the single source of truth for all figures

## Output

- `data/raw/<run_id>.jsonl` — per-request records (§14 schema). The `run_id`
  prefix names the workload: `exp_` (legitimate load), `scale_` (scaling
  sweep), `atk_` (attack suite), `orc_` (oracle ceiling), `abl_` (ablation);
  `run_label` names the experiment cell, which distinguishes ablations that
  share `ZT_MODE=P`.
- `data/raw/attacks/summary.jsonl` — attack outcomes (the primary sweep);
  `attacks_oracle/` and `attacks_ablation/` hold the other two sweeps
- `data/raw/resources*/` — `docker stats` samples taken during each workload
- `data/figures/` — matplotlib figures
- `data/tables/` — CSV tables

## Security guardrails

- **No real endpoints** — all data is synthetic. No Basiq/bank credentials anywhere.
- **Local only** — attack modules target only this testbed.
- **No secrets in repo** — use `.env` (git-ignored).

## Hardware

Tests run on: Apple M-series or x86-64 Linux, ≥ 8 GB RAM, Docker Desktop.
