# bh-exec-fastapi: bench API on FastAPI / Starlette / uvicorn (W4)

What it is: the CONTRACT §3 bench API (`../bench-api.openapi.yaml`) as a FastAPI app. Image
`bh-exec-fastapi:latest`, listening on :8080.

## Versions (pinned, verified inside the image)
- Base image `python:3.12.16-slim-trixie` (Python 3.12.16)
- `fastapi==0.165.0`, `starlette==1.10.0`, `uvicorn==0.54.0`, with h11 0.16.0 as the HTTP/1.1 parser. httptools is not installed (plain `uvicorn`, without `[standard]`), so uvicorn uses h11.
- Server flags: `--no-proxy-headers` (uvicorn otherwise rewrites the client address and scheme from `X-Forwarded-*` for trusted IPs) and `--no-server-header`.

## Build / run / test
```sh
docker build -t bh-exec-fastapi:latest .
docker run --rm -p 127.0.0.1:18080:8080 -v $PWD/logs:/logs \
  -e OVERRIDE=off -e VERIFY_MODE=off bh-exec-fastapi:latest
python3 ../conformance/run_conformance.py http://127.0.0.1:18080 --framework fastapi --log-file logs/executor.jsonl
```
Env: `OVERRIDE`, `VERIFY_MODE`, `FRAMEWORK_TAG` (default `fastapi`), `VERIFIER_URL` (default
`http://verifier:9100/authz/orig`), `LOG_PATH` (default `/logs/executor.jsonl`).
Results: `../conformance/results_A.md` (25/25 and 28/28 in all three configurations).

## Structure
`app.py` is a pure-ASGI stack, outermost first:
1. `BenchLogMiddleware` captures `scope["method"]` (the raw method) and `raw_path`+`query_string` before anything else runs, and writes the log line when the response completes.
2. `HTTPMethodOverrideASGI` is added only when `OVERRIDE=on`.
3. The FastAPI app. `/api/v2` is a separate `FastAPI()` instance attached with `app.mount("/api/v2", v2)`, i.e. a Starlette `Mount`, which is the documented sub-application mechanism (https://fastapi.tiangolo.com/advanced/sub-applications/).

404 and 405 are converted to `{"op_id":"NOT_FOUND"}` with status 404 by an `HTTPException` handler on both apps.

## Method override (`OVERRIDE=on`)
**FastAPI and Starlette ship no method-override mechanism.** Neither the FastAPI middleware docs
(https://fastapi.tiangolo.com/advanced/middleware/) nor the Starlette middleware docs
(https://www.starlette.io/middleware/) list one. On 2026-11-23 we found no ASGI method-override
package on PyPI: `starlette-method-override`, `fastapi-method-override`, `asgi-method-override`,
`asgi-methodoverride`, `starlette-methodoverride` and `fastapi-methodoverride` all return 404 from
the PyPI JSON API. A web search found nothing either. The PyPI package `method-override` 0.3.0 is
WSGI-only and is not usable under ASGI.

So we did not invent semantics. We used the closest widely cited Python pattern: **Flask's
documented `HTTPMethodOverrideMiddleware`** (https://flask.palletsprojects.com/patterns/methodoverrides/),
transliterated line for line from WSGI to ASGI:
- The only source is the `X-HTTP-Method-Override` header. **`_method` is not supported** because the Flask pattern does not read it.
- Allowed targets: GET, HEAD, POST, DELETE, PUT, PATCH, OPTIONS (upper-cased).
- **The original method is not restricted.** A GET with `X-HTTP-Method-Override: DELETE` becomes a DELETE. This was measured: GET + header gives deleteAccount. The other three batch-A frameworks only examine POST.
- If the target is bodyless (GET, HEAD, OPTIONS, DELETE), the body is replaced with an empty one, as Flask sets `CONTENT_LENGTH=0`.

This is a documented deviation from "use the framework's own mechanism". None exists for this framework.

## Router semantics relevant to path normalisation
Measured with `../conformance/probe_router_semantics.py` (raw sockets). See the table in `results_A.md`.
- **Routes match the percent-decoded path.** The ASGI spec gives apps `path` with "percent-encoded sequences and UTF-8 byte sequences decoded into characters" and keeps the original in `raw_path` (https://asgi.readthedocs.io/en/latest/specs/www.html#http-connection-scope). Starlette's `Route` matches against the decoded path. Consequences:
  - `/api/v1/%6De` routes to `me`.
  - `%2F` decodes to `/` before matching, so `{id}` (which excludes `/`) does not match `acc-alice-1%2Fx` and the request gets a 404.
  - `caf%C3%A9` reaches the handler as `café`.
- **Trailing slash:** the Starlette `Router` has `redirect_slashes=True` by default. A path that only matches with the slash added or removed gets a **307** to the other form, and the `Location` is built from the `Host` header (`http://api.bench.test/...`). The sub-app does the same. The 307 is logged as `op_id: NOT_FOUND` with status 307 (CONTRACT interpretation 2).
- No merging of `//`, and no removal of dot segments: both give 404. Matching is case-sensitive.
- `;params` are not special. In a parameter segment they become part of the value (`acc-alice-1;x=1`). On a static segment they give 404.
- **HEAD is not added automatically** for GET routes in FastAPI, so it gets 404. OPTIONS also gets 404.
- uvicorn/h11 accepts a lower-case method token (`get`). It reaches the router and gets 404.
- An absolute-form target (`GET http://host/path`) gets 404: uvicorn/h11 puts the whole target in `path`.
- Query: `request.query_params.get("op")` returns the **last** value for a repeated key (measured).

## Known limitations
- The verifier call uses blocking `urllib` inside FastAPI's threadpool (handlers are `def`), which is fine at harness load.
- `raw_target` is rebuilt as `raw_path + "?" + query_string`. An absolute-form request target is reported as uvicorn exposes it.
- See `../conformance/README.md`, "Contract interpretations", for the shared interpretations (405→404, kept framework redirects, fail-closed verification, `origin-routed` encoding).
