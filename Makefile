# Zero Trust Open Banking Testbed — Makefile
# One-command workflows as required by §2 Definition of Done

.PHONY: up down build test test-unit test-integration \
        provision experiments attacks analysis clean help

SHELL := /bin/bash
COMPOSE := docker compose
CONTROLLER_URL ?= http://localhost:9000
REPETITIONS ?= 30
OUT_DIR ?= data/raw

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

## ─── Provisioning ─────────────────────────────────────────────────────────
provision:
	@echo "==> Running Keycloak provisioning..."
	bash keycloak/provision.sh

## ─── Unit Tests (no Docker needed) ───────────────────────────────────────
test-unit:
	@echo "==> Installing test dependencies..."
	pip install -q -r client_sim/requirements.txt \
	               -r zt-controller/requirements.txt \
	               -r mock-adr-api/requirements.txt
	@echo "==> Running unit tests..."
	# Run each component in isolation to avoid 'app' package name collision
	PYTHONPATH=. python3 -m pytest client_sim/tests/ -v --tb=short 2>&1 | tee data/test_unit_client_sim.log
	PYTHONPATH=.:zt-controller python3 -m pytest zt-controller/tests/ -v --tb=short 2>&1 | tee data/test_unit_zt_controller.log
	PYTHONPATH=.:mock-adr-api python3 -m pytest mock-adr-api/tests/ -v --tb=short 2>&1 | tee data/test_unit_mock_adr.log
	@echo "==> Unit tests complete"

## ─── Integration Tests (requires Docker services) ─────────────────────────
test-integration: up
	@echo "==> Running integration tests (requires running services)..."
	PYTHONPATH=. pytest integration_tests/ -v --tb=short 2>&1 | tee data/test_integration.log

## ─── Full test suite ──────────────────────────────────────────────────────
test: test-unit

## ─── Experiment matrix ────────────────────────────────────────────────────
# Runs E3/E4 performance experiments in each mode via Locust headless
experiments: up
	mkdir -p $(OUT_DIR)
	@for MODE in B0 B1 P; do \
	  echo "==> Running experiments for mode $$MODE..."; \
	  ZT_MODE=$$MODE $(COMPOSE) up -d zt-controller; \
	  sleep 5; \
	  ZT_RUN_ID=exp_$$MODE locust -f load/locustfile.py \
	      --host $(CONTROLLER_URL) \
	      --users 20 --spawn-rate 5 --run-time 30s \
	      --headless --only-summary \
	      2>&1 | tee $(OUT_DIR)/locust_$$MODE.log; \
	done
	@echo "==> Experiments complete. Raw data in $(OUT_DIR)/"

## ─── Attack suite ─────────────────────────────────────────────────────────
attacks: up
	mkdir -p $(OUT_DIR)/attacks
	@echo "==> Running attack suite..."
	PYTHONPATH=. python -m attacks.runner \
	    --controller-b0 $(CONTROLLER_URL) \
	    --controller-b1 $(CONTROLLER_URL) \
	    --controller-p  $(CONTROLLER_URL) \
	    --out-dir $(OUT_DIR)/attacks \
	    --repetitions $(REPETITIONS)
	@echo "==> Attacks complete. Results in $(OUT_DIR)/attacks/"

## ─── Analysis ─────────────────────────────────────────────────────────────
analysis:
	@echo "==> Running analysis pipeline..."
	pip install -q -r analysis/requirements.txt
	PYTHONPATH=. python analysis/make_figures.py
	@echo "==> Figures in data/figures/, tables in data/tables/"

## ─── Full pipeline ─────────────────────────────────────────────────────────
all: up test experiments attacks analysis
	@echo "==> Full pipeline complete."

## ─── Clean ────────────────────────────────────────────────────────────────
clean:
	$(COMPOSE) down -v
	find . -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf data/raw/*.jsonl data/raw/attacks/*.jsonl

help:
	@echo "Targets: up, down, build, provision, test-unit, test, experiments, attacks, analysis, all, clean"
