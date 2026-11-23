# Conformance results: executors batch A (W4)

Run on 2026-11-23 on the shared Mac (Docker Engine 29.4.1, Docker Desktop, arm64). The raw output is
in `out/out_matrix_A.txt` and `out/out_probe_A.txt`. The per-run executor logs and structured
results are in `out/<fw>/<cfg>/{executor.jsonl,result.json}`.

## Images under test

| image | image id | runtime versions (read from inside the image) |
|---|---|---|
| `bh-exec-fastapi:latest` | `sha256:38095ba7d13a…` | Python 3.12.16, FastAPI 0.165.0, Starlette 1.10.0, uvicorn 0.54.0 with h11 0.16.0 (no httptools) |
| `bh-exec-express:latest` | `sha256:e58e05e67c75…` | Node v24.22.3, Express 4.22.3, method-override 3.0.0, path-to-regexp 0.1.13, qs 6.16.2 |
| `bh-exec-django:latest` | `sha256:339fed0294b0…` | Python 3.12.16, Django 6.1.3, gunicorn 27.0.1 (gthread), django-method-override 1.0.4 |
| `bh-exec-go-chi:latest` | `sha256:f66157cd22f8…` | Go 1.27.4 (build), chi v5.5.0, gorilla/handlers v1.5.2, alpine 3.24 runtime |

## Command

```sh
cd binding/harness/executors/conformance
./run_docker_matrix.sh w4 fastapi express django go-chi > out/out_matrix_A.txt 2>&1   # exit 0
```

Each framework runs in 3 configurations. Each container is named `w4-<fw>-<cfg>`, limited to
`--memory 256m`, run one at a time, and removed afterwards. The stub verifier runs on the host, and
the executor reaches it through `VERIFIER_URL=http://host.docker.internal:19100/authz/orig`.

## Required checks

| framework | OVERRIDE=off, VERIFY_MODE=off (logs read from bind-mounted file) | OVERRIDE=on, origin-raw (logs read from `docker logs`) | OVERRIDE=on, origin-routed (logs read from file) |
|---|---|---|---|
| fastapi | **25/25** | **28/28** | **28/28** |
| express | **25/25** | **28/28** | **28/28** |
| django  | **25/25** | **28/28** | **28/28** |
| go-chi  | **25/25** | **28/28** | **28/28** |

25 = 23 op/NOT_FOUND cases (each checks both the response and its log line) + trust-header capture
+ `jti=null` without a DPoP header. The origin modes add 3 verifier-interface checks.

### Verifier view sent by each executor (stub log, identical across all 4 frameworks)

| probe | origin-raw view | origin-routed view | executor result |
|---|---|---|---|
| `GET /api/v1/accounts/acc-alice-1?x=1` (allowed) | `GET /api/v1/accounts/acc-alice-1?x=1` | `GET /api/v1/accounts/acc-alice-1` | 200 getAccount |
| `DELETE /api/v1/accounts/acc-alice-1` (stub denies) | `DELETE /api/v1/accounts/acc-alice-1` | same | 401, logged `denied: true`, `status: 401` |
| `POST /api/v1/accounts/acc-alice-1` + `X-HTTP-Method-Override: DELETE` | **`POST /api/v1/accounts/acc-alice-1`** | **`DELETE /api/v1/accounts/acc-alice-1`** | 200 deleteAccount |

The last row is the G1 override case. In origin-raw mode the verifier is asked about a POST, while
the executor runs `deleteAccount`. In origin-routed mode (defence D-A) the verifier sees the
DELETE it actually guards.

## Override probes (informational, OVERRIDE=on)

| probe | fastapi | express | django | go-chi |
|---|---|---|---|---|
| POST + `X-HTTP-Method-Override: DELETE` | deleteAccount | deleteAccount | deleteAccount | deleteAccount |
| POST `?_method=DELETE` (query) | NOT_FOUND | deleteAccount | NOT_FOUND | deleteAccount |
| POST, form body `_method=DELETE` | NOT_FOUND | deleteAccount | deleteAccount | deleteAccount |
| **GET** + `X-HTTP-Method-Override: DELETE` | **deleteAccount** | getAccount | getAccount | getAccount |

With OVERRIDE=off, every framework returns NOT_FOUND for the three POST probes and getAccount
for the GET probe. FastAPI's mechanism is the ASGI port of the Flask-documented pattern (see
`../fastapi/README.md`). That pattern does not restrict the original method, so a GET can become
a DELETE. The other three mechanisms only examine POST.

## Router-semantics probe (raw sockets, OVERRIDE=off, VERIFY_MODE=off)

Command: `python3 probe_router_semantics.py http://127.0.0.1:<port> --json out/<fw>/probe.json`.
Each cell shows the status and op_id. ✱ marks a request that executed a real operation from a
non-canonical target.

| probe | fastapi | express | django | go-chi |
|---|---|---|---|---|
| `/api/v1/accounts/` | 307 → `/api/v1/accounts` | ✱ 200 listAccounts | 404 | 404 |
| `/api/v1/accounts/acc-alice-1/` | 307 | ✱ 200 getAccount | 404 | 404 |
| `//api/v1/me`, `/api//v1/me` | 404 | 404 | 404 | 404 |
| `/api/v1/./me`, `/api/v1/x/../me`, `%2e%2e` | 404 | 404 | 404 | 404 |
| `/API/V1/ME` | 404 | ✱ 200 me | 404 | 404 |
| `/api/v1/%6De` | ✱ 200 me | 404 | ✱ 200 me | 404 |
| `/api/v1/accounts/acc%2Dalice-1` | 200 id=`acc-alice-1` | 200 id=`acc-alice-1` | 200 id=`acc-alice-1` | 200 id=`acc%2Dalice-1` (raw) |
| `/api/v1/accounts/acc-alice-1%2Fx` | 404 | ✱ 200 id=`acc-alice-1/x` | 404 | ✱ 200 id=`acc-alice-1%2Fx` |
| `/api/v1/public/a%2F..%2Fb` | 404 | ✱ 200 file=`a/../b` | 404 | ✱ 200 file=`a%2F..%2Fb` |
| `/api/v1/me;x=1` | 404 | 404 | 404 | 404 |
| `/api/v1/accounts/acc-alice-1;x=1` | id=`acc-alice-1;x=1` | same | same | same |
| `/api/v1/accounts/caf%C3%A9` | id=`café` | id=`café` | id=`café` | id=`café` (decoded: RawPath unset) |
| `/api/v2//accounts/acc-alice-1` | 404 | ✱ 200 getAccountV2 | 404 | 404 |
| `/api/v2/accounts/acc-alice-1/` | 307 | ✱ 200 getAccountV2 | 404 | 404 |
| absolute-form `GET http://api.bench.test/api/v1/me` | 404 | ✱ 200 me | ✱ 200 me | ✱ 200 me |
| `HEAD /api/v1/me` | 404 | 200 (GET handler, op me) | 200 (GET handler, op me) | 404 |
| `OPTIONS /api/v1/me` | 404 | 404 | 200 `Allow: GET, HEAD, OPTIONS` (op NOT_FOUND) | 404 |
| lower-case `get /api/v1/me` | 404 (h11 accepts it, no route) | 400 from Node, **no log line** | 400 from gunicorn, **no log line** | 404 |
| `?op=freeze&op=close` | close (last wins) | unknown (qs → array) | close (last wins) | freeze (first wins) |
| `?op=close&op=freeze` | freeze | unknown | freeze | close |
| `?x=1;op=close` | unknown | unknown | unknown | unknown |
| `?op[]=close` | unknown | unknown | unknown | unknown |

These are executor-side facts only. Whether a given row produces an oracle hit depends on what the
verifier accepts for the same bytes, which W7's runner measures. The HPP rows are G1/G2 material.
A proof covers neither query, and the four frameworks resolve the same repeated key three different
ways.

## Open issues
- The `VERIFY_MODE` checks used `stub_verifier.py`, not W3's verifier. They need a re-run against the real `verifier` service once W6's topologies exist. No executor change is expected.
- Requests rejected at the HTTP-server layer leave no executor log line (CONTRACT interpretation 3 in `README.md`). W7's oracle must treat a missing line as "not executed".
