# Orchestrator (W6)

Turns a topology YAML (CONTRACT section 5) into a docker compose project:
`gateway` (:8000) → `executor` (:8080), with `verifier` (:9100). It brings the project up, waits for
health and tears it down. It also generates the experiment matrix.

```
orchestrator/
  topology.py        load + validate a topology YAML (on/off booleans normalised; defaults filled in)
  compose.py         render gateway config (gateways/<gw>/render.py) + generated/<id>/docker-compose.yml
  up.py / down.py    python -m orchestrator.up <yaml> / python -m orchestrator.down <yaml|id>
  make_matrix.py     writes topologies/{matrix,pilot,smoke,smokereal}/ and <set>.txt lists
  smoke.py           end-to-end smoke test; writes SMOKE.md + smoke_results.json
  probe/probe.py     healthcheck run by the `probe` sidecar
  stub_verifier/     STUB verifier (always allows, logs view)   -- not a measurement component
  stub_executor/     STUB echo executor (regex routing)         -- not a measurement component
  topologies/        generated topology YAMLs (commit these)
  generated/         generated compose + rendered gateway configs (gitignored)
```

## Setup and usage
```sh
cd binding/harness
python3.12 -m venv orchestrator/.venv
orchestrator/.venv/bin/pip install -r orchestrator/requirements.txt   # PyYAML
# smoke.py also imports W3's minter: pip install -r minter/requirements.txt

orchestrator/.venv/bin/python -m orchestrator.make_matrix
orchestrator/.venv/bin/python -m orchestrator.up orchestrator/topologies/pilot/envoy-default-edge-fastapi-ovoff.yaml
#   -> last stdout line is the host port (127.0.0.1:<host_port>)
orchestrator/.venv/bin/python -m orchestrator.down orchestrator/topologies/pilot/envoy-default-edge-fastapi-ovoff.yaml
```
`up` options:
- `--stubs auto|on|off`. The default `auto` uses a stub only when the real image (`bh-verifier:latest`,
  `bh-exec-<fw>:latest`) is not present locally, and warns on stderr. `off` forces real images.
- `--fresh-logs` deletes `logs/<id>/*.jsonl` first.
- `--timeout` sets the health wait in seconds (default 240).

`generated/<id>/meta.json` records which roles were stubbed. Stub log lines carry `"stub": true`.
**For measurements, use `--stubs off`** so that a missing image fails loudly instead of being silently stubbed.

## What a generated project contains
| service | image | notes |
|---|---|---|
| gateway | `gateway_image` (pinned, see `../gateways/README.md`) | `127.0.0.1:<host_port>:8000`; config bind-mounted read-only from `generated/<id>/gateway/`; mem 512m |
| verifier | `verifier.image` (default `bh-verifier:latest`) or the stub | env `HTU_CANON`, `JTI_CACHE`, `IAT_WINDOW`, `VIEW_MAC`, `VIEW_MAC_KEY`, `AS_PUB_JWK=/keys/as_pub.jwk`, `LOG_PATH`; `harness/keys` → `/keys:ro`; `harness/logs/<id>` → `/logs`; mem 256m |
| executor | `executor_image` (default `bh-exec-<fw>:latest`) or the stub | env `OVERRIDE`, `VERIFY_MODE` (origin-raw for placement origin/both, else off; overridable with a topology `verify_mode:` key), `FRAMEWORK_TAG`, `LOG_PATH`; `harness/logs/<id>` → `/logs`; mem 640m |
| probe | `python:3.12.16-slim-trixie` | `sleep infinity` with a healthcheck running `probe.py`. `up` uses `docker compose up -d --wait`, so it returns only when the probe is healthy: verifier `/health` 2xx, executor `/api/v1/health` < 500, gateway TCP :8000 open. mem 64m |

Optional topology keys beyond the CONTRACT example (all have defaults):
- `verifier.image`, `verifier.jti_cache`, `verifier.iat_window`, `verifier.view_mac_key`;
- `verify_mode`;
- `executor_image: stub` or `verifier.image: stub`, which force a stub.

## Topology sets (`make_matrix.py`)
- `matrix/`: 864 topologies, from 6 gateways × 3 profiles × 3 placements × 8 frameworks
  (fastapi, express, django, go-chi, spring, aspnet, rails, laravel) × override off/on. The id is
  `<gw>-<profile>-<placement>-<fw>-ov<off|on>`, and `host_port = 18000 + index`.
- `pilot/`: 24 topologies, from envoy/traefik/nginx × default × edge × fastapi/express/spring/aspnet × off/on. Each reuses its matrix port.
- `smoke/`: 18 topologies, from 6 gateways × 3 profiles at edge, with the stub verifier and stub executor (ports 19000+).
- `smokereal/`: the same 18 with the real W3 verifier and the stub executor (ports 19100+).

## How it was tested
See `SMOKE.md`: every gateway × profile at `placement=edge` was brought up, sent one canonical
request with `curl --path-as-is`, checked by jti in both logs, and torn down. This ran twice. Set A
used the stub verifier and passed 18/18. Set B used the real W3 `bh-verifier:latest` and also passed
18/18, with an `allow` decision every time. One topology was up at
a time, under compose project prefix `w6-bh-`.

## Contract interpretations
1. **Project name.** The CONTRACT says `bh-<id>`, while rule 0 says to prefix with the worker tag. The
   default is `bh-<id>`. Set `BH_PROJECT_PREFIX` (for example `w6-bh-`) to add a tag. W6's smoke runs used `w6-bh-`.
   Containers are named `<project>-<service>-1` by compose.
2. **Health waiting** uses a `probe` sidecar rather than healthchecks inside the gateway, verifier
   and executor images, because the distroless and framework images have no common shell or curl. The
   executor counts as healthy on any HTTP status below 500, because in origin modes a real executor
   may answer 401 to an unauthenticated health request. Probe requests to `/api/v1/health` go
   straight to the executor, not through the gateway, and appear in `executor.jsonl` with `jti: null`.
3. **Keys for the real verifier.** `harness/keys` is mounted at `/keys:ro`, with `AS_PUB_JWK=/keys/as_pub.jwk`.
   W3's README says the image bakes in the key at build time, and this mount keeps the two in step if the keys are regenerated.
4. **YAML on/off.** PyYAML reads bare `off`/`on` as booleans, so both forms are accepted and
   normalised to the strings `on`/`off`. Generated YAMLs quote them.
5. **Logs** are appended across runs. `up --fresh-logs` clears them, and the smoke test always uses it.
6. **`verify_mode`** is an optional topology key, so the D-A defence (`origin-routed`) can reuse the
   same topologies without a CONTRACT change. When it is absent, the placement decides, as the CONTRACT says.
7. **Strict gateway profiles** add harness-defined deny rules where a gateway has no native toggle.
   See `../gateways/README.md`.

## Known limitations
- The stubs exist only for wiring. The stub executor applies no framework semantics: no decoding,
  no override, regex routing. The stub verifier always allows.
- Up times are dominated by Kong and APISIX start-up (see SMOKE.md). Each topology runs four containers.
- Executor images (`bh-exec-*`) were not available when this was written, so no matrix or pilot
  topology has been brought up with real executors yet.
- Default memory limits total about 1.5 GB per topology. Keep at most 2 topologies up at once on the shared machine.
