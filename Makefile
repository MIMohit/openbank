# Zero Trust Open Banking Testbed — Makefile
# One-command workflows as required by §2 Definition of Done

.PHONY: up down build test test-unit test-integration reset-state \
        provision experiments scaling attacks attacks-oracle attacks-adaptive \
        ablation analysis figures clean help

SHELL := /bin/bash
COMPOSE := docker compose
CONTROLLER_URL ?= http://localhost:9000
KEYCLOAK_URL ?= http://localhost:8080
REPETITIONS ?= 30
OUT_DIR ?= data/raw
LOAD_USERS ?= 20
LOAD_SPAWN_RATE ?= 5
LOAD_RUN_TIME ?= 60s
ZT_CONTROLLER_CONTAINER ?= open-bank-zt-controller-1
INTERNAL_SECRET ?= zt-internal-only

# Analysis needs numpy >= 2.1, which needs Python >= 3.10; the system python3
# on the reference host is 3.9. Build an isolated venv from the newest
# interpreter available rather than fighting PEP 668 on a Homebrew python.
ANALYSIS_VENV ?= analysis/.venv
ANALYSIS_PY := $(ANALYSIS_VENV)/bin/python3
PYTHON310 := $(shell command -v python3.13 || command -v python3.12 || command -v python3.11 || command -v python3.10 || command -v python3)

## ─── Bring-up ─────────────────────────────────────────────────────────────
up:
	@echo "==> Starting all services..."
	$(COMPOSE) up --build -d
	@echo "==> Waiting for Keycloak to be healthy..."
	@until docker compose ps keycloak | grep -q "(healthy)"; do sleep 3; done
	@echo "==> All services healthy."

down:
	$(COMPOSE) down -v

build:
	$(COMPOSE) build

## ─── Harness control plane ────────────────────────────────────────────────
# Drops the controller's in-memory continuous-trust state so one workload does
# not inherit the previous one's device, geo and rate history.
reset-state:
	@curl -sf -X POST -H "x-zt-admin: $(INTERNAL_SECRET)" \
	    $(CONTROLLER_URL)/admin/reset-state > /dev/null || true

## ─── Provisioning ─────────────────────────────────────────────────────────
provision:
	@echo "==> Running Keycloak provisioning..."
	bash keycloak/provision.sh

## ─── Unit Tests (no Docker needed) ───────────────────────────────────────
test-unit:
	@echo "==> Installing test dependencies..."
	python3 -m pip install -q -r client_sim/requirements.txt \
	               -r zt-controller/requirements.txt \
	               -r mock-adr-api/requirements.txt
	@echo "==> Running unit tests..."
	@mkdir -p data
	# Run each component in isolation to avoid 'app' package name collision
	PYTHONPATH=. python3 -m pytest client_sim/tests/ -v --tb=short 2>&1 | tee data/test_unit_client_sim.log
	PYTHONPATH=.:zt-controller python3 -m pytest zt-controller/tests/ -v --tb=short 2>&1 | tee data/test_unit_zt_controller.log
	PYTHONPATH=.:mock-adr-api python3 -m pytest mock-adr-api/tests/ -v --tb=short 2>&1 | tee data/test_unit_mock_adr.log
	@echo "==> Unit tests complete"

## ─── Integration Tests (requires Docker services) ─────────────────────────
test-integration: up
	@echo "==> Running integration tests (requires running services)..."
	PYTHONPATH=. python3 -m pytest integration_tests/ -v --tb=short 2>&1 | tee data/test_integration.log

## ─── Full test suite ──────────────────────────────────────────────────────
test: test-unit

## ─── Experiment matrix ────────────────────────────────────────────────────
# E3/E4 performance + E2 false-challenge, one Locust run per configuration.
# A background docker-stats sampler runs alongside each workload so Table 4's
# CPU/memory overhead is measured rather than asserted.
experiments: up
	@mkdir -p $(OUT_DIR) data/raw/resources
	# The controller appends to data/raw/<run_id>.jsonl across container
	# restarts, so a re-run would silently mix this run's records with the
	# previous one's. Clear this target's own outputs only.
	@rm -f data/raw/resources/*.csv $(OUT_DIR)/exp_*.jsonl
	@for MODE in B0 B1 P; do \
	  echo "==> Running experiments for mode $$MODE..."; \
	  ZT_MODE=$$MODE ZT_RUN_ID=exp_$$MODE ZT_RUN_LABEL=$$MODE $(COMPOSE) up -d zt-controller; \
	  sleep 6; \
	  $(MAKE) --no-print-directory reset-state; \
	  ./scripts/sample_resources.sh $$MODE data/raw/resources/$$MODE.csv $(ZT_CONTROLLER_CONTAINER) & \
	  SAMPLER=$$!; \
	  ZT_MODE=$$MODE KEYCLOAK_URL=$(KEYCLOAK_URL) python3 -m locust -f load/locustfile.py \
	      --host $(CONTROLLER_URL) \
	      --users $(LOAD_USERS) --spawn-rate $(LOAD_SPAWN_RATE) --run-time $(LOAD_RUN_TIME) \
	      --headless --only-summary \
	      2>&1 | tee $(OUT_DIR)/locust_$$MODE.log; \
	  kill -TERM $$SAMPLER 2>/dev/null || true; wait $$SAMPLER 2>/dev/null || true; \
	done
	@echo "==> Experiments complete. Raw data in $(OUT_DIR)/"

## ─── Load scaling sweep (RQ2: "across increasing load") ───────────────────
# `experiments` measures one concurrency level; RQ2 asks how the overhead moves
# as load rises, which needs several. Each cell is a short Locust run at a fixed
# user count; achieved throughput is recomputed from the controller's own
# records in analysis rather than scraped from Locust's summary.
SCALING_USERS ?= 5 10 20 40
SCALING_RUN_TIME ?= 30s

scaling: up
	@mkdir -p $(OUT_DIR)
	@rm -f $(OUT_DIR)/scale_*.jsonl
	@for MODE in B0 B1 P; do \
	  for U in $(SCALING_USERS); do \
	    echo "==> Scaling: mode $$MODE, $$U users..."; \
	    ZT_MODE=$$MODE ZT_RUN_ID=scale_$${MODE}_$${U} ZT_RUN_LABEL=$$MODE \
	      $(COMPOSE) up -d zt-controller; \
	    sleep 6; \
	    $(MAKE) --no-print-directory reset-state; \
	    ZT_MODE=$$MODE KEYCLOAK_URL=$(KEYCLOAK_URL) python3 -m locust -f load/locustfile.py \
	        --host $(CONTROLLER_URL) \
	        --users $$U --spawn-rate $$U --run-time $(SCALING_RUN_TIME) \
	        --headless --only-summary \
	        2>&1 | tail -20; \
	  done; \
	done
	@echo "==> Scaling sweep complete."

## ─── Attack suite ─────────────────────────────────────────────────────────
# The testbed runs a single ZT Controller instance, so each config (B0/B1/P)
# is tested by restarting the controller with a different ZT_MODE and running
# the attack suite against it, rather than by hitting three separate ports.
attacks: up
	@mkdir -p $(OUT_DIR)/attacks
	@rm -f $(OUT_DIR)/attacks/summary.jsonl $(OUT_DIR)/attacks/A*_B0.jsonl \
	       $(OUT_DIR)/attacks/A*_B1.jsonl $(OUT_DIR)/attacks/A*_P.jsonl \
	       $(OUT_DIR)/atk_*.jsonl
	@echo "==> Running attack suite (organic — no oracle tag)..."
	@for MODE in B0 B1 P; do \
	  echo "==> Attacks: config $$MODE..."; \
	  ZT_MODE=$$MODE ZT_RUN_ID=atk_$$MODE ZT_RUN_LABEL=$$MODE $(COMPOSE) up -d zt-controller; \
	  sleep 6; \
	  PYTHONPATH=. KEYCLOAK_URL=$(KEYCLOAK_URL) python3 -m attacks.runner \
	      --controller-b0 $(CONTROLLER_URL) \
	      --controller-b1 $(CONTROLLER_URL) \
	      --controller-p  $(CONTROLLER_URL) \
	      --out-dir $(OUT_DIR)/attacks \
	      --repetitions $(REPETITIONS) \
	      --modes $$MODE; \
	done
	@echo "==> Attacks complete. Results in $(OUT_DIR)/attacks/"

## ─── Attack suite, oracle ceiling (secondary measurement) ─────────────────
# Re-runs the suite with `x-attack-context: true` and risk rule R7 enabled, so
# every attack request tells the risk engine it is an attack. That is an oracle
# supplied by the adversary, not detection; it bounds how much the enforcement
# pipeline could block if detection were perfect. Reported separately and never
# mixed into the primary tables.
attacks-oracle: up
	@mkdir -p $(OUT_DIR)/attacks_oracle
	@rm -f $(OUT_DIR)/attacks_oracle/*.jsonl $(OUT_DIR)/orc_*.jsonl
	@for MODE in B1 P; do \
	  echo "==> Oracle-ceiling attacks: config $$MODE..."; \
	  ZT_MODE=$$MODE ZT_RUN_ID=orc_$$MODE ZT_RUN_LABEL=$$MODE-oracle \
	  ZT_ORACLE_ATTACK_CONTEXT=true $(COMPOSE) up -d zt-controller; \
	  sleep 6; \
	  PYTHONPATH=. KEYCLOAK_URL=$(KEYCLOAK_URL) python3 -m attacks.runner \
	      --controller-b0 $(CONTROLLER_URL) \
	      --controller-b1 $(CONTROLLER_URL) \
	      --controller-p  $(CONTROLLER_URL) \
	      --out-dir $(OUT_DIR)/attacks_oracle \
	      --repetitions $(REPETITIONS) \
	      --oracle-tag \
	      --modes $$MODE; \
	done
	@echo "==> Oracle-ceiling attacks complete."

## ─── Adaptive adversary (A7) ──────────────────────────────────────────────
# A4 measures an adversary who makes no attempt to evade the contextual rules.
# A7 measures the same account takeover played by an adversary who does: they
# pace requests below the absolute call-rate threshold and mimic the victim's
# self-reported context, both of which the threat model already grants them.
# What remains is the one signal they cannot forge — a cnf.jkt this subject has
# never used — so A7 measures whether that signal is actionable on its own.
#
# Three cells: the FAPI 2.0 baseline, P at the shipped operating point, and P
# at the recalibrated threshold the sensitivity sweep identifies. Everything is
# written to its own output directory and its own run labels, so adding this
# measurement cannot change any number in the primary tables.
ADAPTIVE_CELLS := B1-adaptive P-adaptive P-adaptive-slow P-adaptive-tau030 P-adaptive-slow-tau030

attacks-adaptive: up
	@mkdir -p $(OUT_DIR)/attacks_adaptive
	@rm -f $(OUT_DIR)/attacks_adaptive/*.jsonl $(OUT_DIR)/adp_*.jsonl
	@for CELL in $(ADAPTIVE_CELLS); do \
	  echo "==> Adaptive-adversary cell: $$CELL"; \
	  MODE=P; TAU=0.4; PACE=2.5; \
	  case $$CELL in \
	    B1-adaptive)         MODE=B1 ;; \
	    P-adaptive)          MODE=P ;; \
	    P-adaptive-slow)     MODE=P; PACE=4.0 ;; \
	    P-adaptive-tau030)   MODE=P; TAU=0.3 ;; \
	    P-adaptive-slow-tau030) MODE=P; TAU=0.3; PACE=4.0 ;; \
	  esac; \
	  ZT_MODE=$$MODE ZT_RUN_ID=adp_$$CELL ZT_RUN_LABEL=$$CELL \
	  ZT_RISK_THRESHOLD_ALLOW=$$TAU $(COMPOSE) up -d zt-controller; \
	  sleep 6; \
	  PYTHONPATH=. KEYCLOAK_URL=$(KEYCLOAK_URL) python3 -m attacks.runner \
	      --controller-b0 $(CONTROLLER_URL) \
	      --controller-b1 $(CONTROLLER_URL) \
	      --controller-p  $(CONTROLLER_URL) \
	      --out-dir $(OUT_DIR)/attacks_adaptive \
	      --repetitions $(REPETITIONS) \
	      --only A7 --pace-seconds $$PACE \
	      --modes $$MODE --label $$CELL; \
	done
	@echo "==> Adaptive-adversary run complete. Results in $(OUT_DIR)/attacks_adaptive/"

## ─── Ablation matrix (§7.4, RQ3) ──────────────────────────────────────────
# Each cell restarts the controller with one enforcement component removed and
# runs both the attack suite and the drifting legitimate workload against it,
# so Table 5 carries a security column and a usability column per component.
#   P                       full continuous enforcement
#   P-minus-device-binding  ZT_CHECK_DEVICE_BINDING=false — drops the cnf.jkt
#                           binding check and risk rules R1/R2
#   P-minus-context         ZT_ENABLE_TELEMETRY=false — drops the telemetry PIP
#                           and with it geo/velocity (R3), session continuity
#                           (R5) and DPoP-failure history (R6). Device binding
#                           is deliberately NOT part of "context": it is keyed
#                           on the token's cnf.jkt rather than on the PIP, so
#                           the two components stay separable.
#   P-minus-velocity        ZT_ENABLE_VELOCITY=false — drops call-rate rule R4
#                           only (a strict subset of P-minus-context)
#   B1                      FAPI 2.0 baseline, for reference in the same sweep
ABLATION_CELLS := P P-minus-device-binding P-minus-context P-minus-velocity B1

ablation: up
	@mkdir -p $(OUT_DIR)/attacks_ablation data/raw/resources_ablation
	@rm -f $(OUT_DIR)/attacks_ablation/*.jsonl data/raw/resources_ablation/*.csv \
	       $(OUT_DIR)/abl_*.jsonl
	@for CELL in $(ABLATION_CELLS); do \
	  echo "==> Ablation cell: $$CELL"; \
	  MODE=P; DEVBIND=; TELEM=; VELO=; \
	  case $$CELL in \
	    P) ;; \
	    P-minus-device-binding) DEVBIND=false ;; \
	    P-minus-context)        TELEM=false ;; \
	    P-minus-velocity)       VELO=false ;; \
	    B1)                     MODE=B1 ;; \
	  esac; \
	  ZT_MODE=$$MODE ZT_RUN_ID=abl_$$CELL ZT_RUN_LABEL=$$CELL \
	  ZT_CHECK_DEVICE_BINDING=$$DEVBIND ZT_ENABLE_TELEMETRY=$$TELEM \
	  ZT_ENABLE_VELOCITY=$$VELO $(COMPOSE) up -d zt-controller; \
	  sleep 6; \
	  PYTHONPATH=. KEYCLOAK_URL=$(KEYCLOAK_URL) python3 -m attacks.runner \
	      --controller-b0 $(CONTROLLER_URL) \
	      --controller-b1 $(CONTROLLER_URL) \
	      --controller-p  $(CONTROLLER_URL) \
	      --out-dir $(OUT_DIR)/attacks_ablation \
	      --repetitions $(REPETITIONS) \
	      --modes $$MODE --label $$CELL; \
	  $(MAKE) --no-print-directory reset-state; \
	  ./scripts/sample_resources.sh $$CELL data/raw/resources_ablation/$$CELL.csv $(ZT_CONTROLLER_CONTAINER) & \
	  SAMPLER=$$!; \
	  ZT_MODE=$$MODE KEYCLOAK_URL=$(KEYCLOAK_URL) python3 -m locust -f load/locustfile.py \
	      --host $(CONTROLLER_URL) \
	      --users $(LOAD_USERS) --spawn-rate $(LOAD_SPAWN_RATE) --run-time $(LOAD_RUN_TIME) \
	      --headless --only-summary \
	      2>&1 | tee $(OUT_DIR)/locust_abl_$$CELL.log; \
	  kill -TERM $$SAMPLER 2>/dev/null || true; wait $$SAMPLER 2>/dev/null || true; \
	done
	@echo "==> Ablation complete. Results in $(OUT_DIR)/attacks_ablation/"

## ─── Analysis ─────────────────────────────────────────────────────────────
$(ANALYSIS_PY):
	@echo "==> Creating analysis venv with $(PYTHON310)..."
	$(PYTHON310) -m venv $(ANALYSIS_VENV)
	$(ANALYSIS_PY) -m pip install -q --upgrade pip
	$(ANALYSIS_PY) -m pip install -q -r analysis/requirements.txt

analysis: $(ANALYSIS_PY)
	@echo "==> Running analysis pipeline..."
	PYTHONPATH=. $(ANALYSIS_PY) analysis/make_figures.py
	@$(MAKE) --no-print-directory figures
	@echo "==> Tables in data/tables/; manuscript figures in paper/figures/"

## ─── Manuscript figures ───────────────────────────────────────────────────
# The diagrams and the result plots the manuscript cites, as vector PDF for
# typesetting and 400 dpi PNG for preview. Result plots read only the CSVs in
# data/tables/ and the raw records, so no value in a figure can drift away from
# the table that reports it.
figures: $(ANALYSIS_PY)
	@echo "==> Building manuscript figures..."
	PYTHONPATH=. $(ANALYSIS_PY) analysis/paper_figures.py

## ─── Full pipeline ─────────────────────────────────────────────────────────
all: up test experiments scaling attacks attacks-oracle attacks-adaptive ablation analysis
	@echo "==> Full pipeline complete."

## ─── Clean ────────────────────────────────────────────────────────────────
clean:
	$(COMPOSE) down -v
	find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf data/raw/*.jsonl data/raw/attacks/*.jsonl \
	       data/raw/attacks_oracle/*.jsonl data/raw/attacks_ablation/*.jsonl \
	       data/raw/attacks_adaptive/*.jsonl \
	       data/raw/resources/*.csv data/raw/resources_ablation/*.csv

help:
	@echo "Targets: up, down, build, provision, test-unit, test, experiments,"
	@echo "         scaling, attacks, attacks-oracle, attacks-adaptive, ablation,"
	@echo "         analysis, figures, all, clean"
