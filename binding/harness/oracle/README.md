# oracle — correlator + ddmin minimiser (W7)

Implements `oracle/oracle_spec.md` (owned by W2), which makes CONTRACT §6 precise. Joins
runner/verifier/executor logs on the proof `jti`, applies the hit definition, assigns
severity, classifies edge cases, raises the G3 propagation predicate, deduplicates into
root-cause signatures, and writes the outputs.

> `oracle_spec.md` is owned by W2; this directory owns everything else.

## Contents
- `correlate.py` — the oracle. Pure function `correlate(runner, verifier, executor, topo,
  ground_truth, primitive_catalogue) -> OracleResult`, plus `write_outputs` and a CLI.
- `minimise.py` — delta-debugging (`ddmin`) over a hit's **primitive list**
  (`ddmin_primitives`) and over the **request bytes** (`ddmin_bytes`). `test(...)` is
  supplied by the caller's runner+oracle round-trip, so the module is pure and unit-tested
  with a synthetic predicate.

## Run / test
```
cd binding/harness
python -m oracle.correlate --log-dir logs/<id> \
    --topology orchestrator/topologies/.../<id>.yaml \
    --ground-truth logs/groundtruth/<framework>.jsonl \
    --summary-csv logs/summary.csv
python -m pytest oracle/tests -q      # 25 tests over synthetic logs
```

## Outputs (oracle_spec §11)
- `logs/<id>/hits.jsonl` — one line per hit (sorted by `case_id` for determinism), with
  `deviation_kinds`, `severity`, views, `signature`, `minimal` flag, `rerun: pending`.
- `logs/<id>/propagation.jsonl` — G3 propagation findings (§8), counted separately.
- `logs/<id>/oracle_other.jsonl` — B0 verifier-bypass, uncorrelated, orphan, not-executed,
  nonconformant records.
- `summary.csv` — one idempotent row per topology.

## What is a hit (oracle_spec §4)
Accepted (verifier allow / executor not denied per placement) **and** a different operation
— `op_id ∉ {base, NOT_FOUND}`, or same `op_id` with different `path_params` (resource
substitution) — **and** status < 400. Severity S1/S2/S3 from the executed record (§5).

## Tested edge cases
Missing `jti`, unmatched records (runner↔executor↔verifier), `NOT_FOUND`, `denied`,
status ≥ 400, origin-placement denied-flag fallback, verifier-bypass (B0), nonconformant
ground truth, orphan verifier, uncorrelated (null-jti) executor records, resource
substitution, the full severity table, G3 propagation (incl. underscore folding),
minimisation subset-folding, and byte-identical determinism across re-runs.

## Contract interpretations (and where spec ≠ CONTRACT)
Per W2's instruction, where `oracle_spec.md` and CONTRACT §6 differ, the **spec wins**:
- **Resource substitution** (same `op_id`, different `path_params`) counts as a hit and is
  **S1**. CONTRACT §6's S1 "different {id}/owner" would otherwise never fire.
- **G3 propagation without an op change is NOT a §4 binding hit**; it is reported
  separately in `propagation.jsonl` and counted apart from binding hits.
- **Verifier bypass is class B0**, not a binding hit (reported in `oracle_other.jsonl`).
- **Ground truth drives `op(π)`.** Without a ground-truth file the oracle falls back to
  `op_id ≠ base_op_id` and **cannot** detect resource substitution or reliably distinguish
  `route` vs `dispatch` deviation (it uses a method-equality heuristic). Supply
  `logs/groundtruth/<framework>.jsonl` (produced by `runner --direct`) for full fidelity.
- **Determinism/reruns**: the oracle emits `rerun: pending`; the 3× rerun confirmation
  (spec §10) is driven by the orchestration layer, not this pure function.
- Signature minimisation folds a primitive set `P` into `P' ⊂ P` when both are hits on the
  same topology/base-op/deviation — a lightweight offline version of `ddmin`; the
  byte/primitive `ddmin` in `minimise.py` is for per-hit root-causing.
