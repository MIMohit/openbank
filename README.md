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
make attacks   # run A1–A6 attack suite
make analysis  # generate figures and tables
```

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

Individual feature flags for ablations:

```bash
ZT_ENABLE_TELEMETRY=false ZT_ENABLE_RISK_POLICY=false docker compose up -d zt-controller
```

## Experiment matrix

| Experiment | Command |
|------------|---------|
| E1 Security (attacks) | `make attacks` |
| E3/E4 Performance | `make experiments` |
| Analysis | `make analysis` |

## Reproducibility

- All random seeds fixed (`GLOBAL_SEED=42`, `MOCK_ADR_SEED=42`)
- Docker images pinned by version tag (see `docker-compose.yml`)
- Python dependencies pinned in `requirements.txt` files
- JSONL output in `data/raw/` is the single source of truth for all figures

## Output

- `data/raw/*.jsonl` — per-request records (§14 schema)
- `data/raw/attacks/*.jsonl` — attack outcomes
- `data/figures/` — matplotlib figures
- `data/tables/` — CSV tables

## Security guardrails

- **No real endpoints** — all data is synthetic. No Basiq/bank credentials anywhere.
- **Local only** — attack modules target only this testbed.
- **No secrets in repo** — use `.env` (git-ignored).

## Hardware

Tests run on: Apple M-series or x86-64 Linux, ≥ 8 GB RAM, Docker Desktop.
