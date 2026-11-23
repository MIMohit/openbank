# runner — raw-socket matrix runner (W7)

For each mutation case: mint a fresh token+proof bound to the **base op's** canonical
(htm, htu), inject them into the case's raw bytes, send the exact bytes over a raw TCP
socket, and record `runner.jsonl` (CONTRACT §6).

## Contents
- `run_matrix.py` — the runner CLI.
- `minter_adapter.py` — prefers W3's real minter (`minter.dpop.headers_for` +
  `decode_unverified`), falls back to the shim. Normalises both to
  `mint(client, htm, htu) -> (authz, dpop, jti)`.
- `minter_shim.py` — a self-contained reference minter (RFC 9449 / CONTRACT §2 ES256
  tokens and proofs) used when W3's minter is unavailable. It writes its own ephemeral TEST
  keys to `runner/.shimkeys/` on demand (gitignored; deleted here because the real W3
  minter is present and preferred) so it never touches W3's `harness/keys/`.
- `build_groundtruth.py` — joins a **direct** run's `runner.jsonl` + `executor.jsonl` on
  `jti` and emits `logs/groundtruth/<framework>.jsonl` (`{base_op_id, op_id, path_params,
  status}`) — the `op(π)` file the oracle needs for resource-substitution detection
  (oracle_spec §2).

## Run
```
cd binding/harness
# Against a running stack by port (e.g. a W6 topology that is already up):
python -m runner.run_matrix --host-port 19006 --topology-id smoke-nginx-default-edge \
    --cases cases.jsonl --minter w3

# Against a W6 topology YAML (reads id + host_port):
python -m runner.run_matrix --topology orchestrator/topologies/pilot/envoy-default-edge-fastapi-ovoff.yaml

# Ground-truth mode: hit the executor directly (no gateway), baseline cases only:
python -m runner.run_matrix --host-port 18781 --direct --topology-id w7-groundtruth-fastapi
python -m runner.build_groundtruth \
    --runner logs/w7-groundtruth-fastapi/runner.jsonl \
    --executor logs/w7-groundtruth-fastapi/executor.jsonl \
    --framework fastapi --out logs/groundtruth/fastapi.jsonl
python -m pytest runner/tests -q
```
If `--cases` is omitted, depth-1 cases are generated in-process.

## runner.jsonl fields
`ts, case_id, base_op_id, base_method, base_path, primitive_ids, depth, groups, client,
jti, mode (gateway|direct), topology, host, host_port, htm, htu, minter (w3|shim),
sent_bytes_len, status, resp_framing, resp_body_len, resp_body_sha256, resp_op_id, error`.

The `jti` is the correlation key the oracle joins on (oracle_spec §1).

## Verified end-to-end (2026-11-23, real components)
Full pipeline on a real `nginx-default-edge-fastapi` topology (W6 orchestrator,
`--stubs off`: nginx 1.30.7-alpine gateway → `bh-verifier:latest` in edge placement →
`bh-exec-fastapi:latest`), brought up under `BH_PROJECT_PREFIX=w7-bh-` on host port 18788:

1. Direct ground-truth run (executor alone, `VERIFY_MODE=off`) → all 13 base ops reached
   their canonical `op_id`; `build_groundtruth` wrote `logs/groundtruth/fastapi.jsonl`.
2. Minted real W3 proofs and sent the depth-1 matrix (948 cases) as raw bytes through the
   gateway: 948 sent, 0 transport errors.
3. Oracle over the joined logs (948 cases, 659 verifier-accepted): **20 raw hits (13 S1,
   7 S2), 15 unique signatures, max_res_hat = 3** (`accountAction.freeze` resolved under one
   proof to {freeze, close, unknown}), 117 G3 propagation findings, 9 uncorrelated
   (null-`jti`) executor records, 0 B0 verifier-bypass. Summary: `logs/w7-smoke-summary.csv`;
   hits: `logs/w7smoke-nginx-fastapi/hits.jsonl`.

Representative hits: G1 dispatch (`op=close`/`op=CLOSE`/`op=freeze&op=close` HPP/case
variants flip `accountAction.*`; `operationName` and `_method` form swaps flip the graphql
op to `deleteProfile`/`unknown`); G2 `#frag` on the wire changes the decoded `{id}`
path param (flagged `resource`, pending reviewer confirmation per oracle_spec §9).
Topology and ground-truth container were torn down; no `w7-` containers or `w7smoke-*`
generated dir remain.

## Limitations / contract interpretations
- **Minter interface**: the CONTRACT does not fix W3's exact API, so the adapter probes
  for `minter.dpop.headers_for(client, htm, htu, variant=...)` + `decode_unverified`
  (W3's actual shape). If W3 changes it, update `minter_adapter._try_import_w3`. Force the
  shim with `W7_FORCE_SHIM=1` (used by tests) or `--minter shim`.
- **`htu` has no query** (CONTRACT §1): bound to `http://api.bench.test` + base path.
- `--direct` defaults to baseline (depth-0) cases, which is exactly `op(π)`; `--direct-all`
  sends the whole matrix at the executor.
- The shim is a convenience for offline testing; experiments use `--minter w3`.
- **Orchestrator ownership (contract interpretation).** `orchestrator/` is W6-owned, but
  CONTRACT §5 makes `python -m orchestrator.up <topology>` the sanctioned way to start a
  topology, and that tool necessarily writes `orchestrator/generated/<id>/`. For the smoke
  I invoked it as a provided tool (not editing W6 source) under my own
  `BH_PROJECT_PREFIX=w7-bh-` tag with a unique id/port, and removed the generated dir and
  all `w7-` containers afterwards. I did not author anything under `orchestrator/`.
- **Ground truth needs a direct run.** `build_groundtruth.py` only consumes baseline
  (depth-0) records; run `run_matrix --direct` (baselines only by default) against the
  executor image with `VERIFY_MODE=off` before correlating, per oracle_spec §2.
