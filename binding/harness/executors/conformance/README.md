# Executor conformance test (W4)

What it is: a framework-agnostic check that an executor implements the bench API in
`binding/CONTRACT.md` §3 and `../bench-api.openapi.yaml`. W4 and W5 use it for every framework.
It needs only the Python 3.12 standard library, so `requirements.txt` is intentionally empty.

| file | purpose |
|---|---|
| `run_conformance.py` | the test. Sends the canonical request for every op_id, plus query/body dispatch variants and NOT_FOUND probes, and asserts `op_id`, status, response shape and the log line |
| `stub_verifier.py` | **stub** of W3's `/authz/orig`, used only to test `VERIFY_MODE`. It does no crypto: it records the view it receives and denies when the unverified DPoP `jti` starts with `deny-` |
| `run_docker_matrix.sh` | runs the test against `bh-exec-<fw>:latest` in 3 configurations, with containers named `<prefix>-<fw>-<cfg>` and removed afterwards |
| `probe_router_semantics.py` | raw-socket probe of path and method normalisation (trailing slash, `//`, dot segments, `%2F`, `;params`, case, HEAD/OPTIONS, HPP). It is evidence for the READMEs, not pass/fail |
| `results_A.md` | W4's results for fastapi, express, django and go-chi |
| `out/` | raw evidence: per-run `executor.jsonl`, `result.json` and `probe.json`, plus `out_matrix_A.txt` and `out_probe_A.txt` (W4) |

## How to run (for W5 and anyone else)

```sh
# one executor, OVERRIDE=off VERIFY_MODE=off, checking logs through the bind-mounted file
docker run -d --name w5-spring -p 127.0.0.1:18080:8080 -v $PWD/logs:/logs bh-exec-spring:latest
python3 run_conformance.py http://127.0.0.1:18080 --framework spring --log-file logs/executor.jsonl
# ... or read the stdout copy instead of the file
python3 run_conformance.py http://127.0.0.1:18080 --framework spring --docker-logs w5-spring

# the full matrix (off/off, on/origin-raw, on/origin-routed) for your frameworks
BASE_PORT=18600 STUB_PORT=19200 ./run_docker_matrix.sh w5 spring aspnet rails laravel > out/out_matrix_B.txt 2>&1; echo $?
```

`--override on` adds 4 informational override probes (header, `?_method=`, form-body `_method`,
header on a GET). The result is recorded and not asserted, because support legitimately differs
by framework. `--verify-mode origin-raw|origin-routed --stub-log F` adds 2–3 asserted probes. They
check the exact `X-Original-Method` / `X-Original-URI` / `X-Original-Host` that the executor sent,
that `Authorization` and `DPoP` were forwarded, that a deny gives 401, and that the log line carries
`"denied": true`. Executor containers reach the host stub at `http://host.docker.internal:19100/authz/orig`
(Docker Desktop). Pass that as `VERIFIER_URL`. Every executor reads `VERIFIER_URL` (default
`http://verifier:9100/authz/orig`).

The exit code is 0 only if every required check passes. `--json` writes the full structured result.

### Required checks
1. The 23 cases in `CASES`, covering all 17 op_ids and 3 NOT_FOUND shapes (unknown path, known path with wrong method, unknown path under the `/api/v2` mount). Each is checked for status, `op_id`, response keys `op_id/framework/method/path_params`, `path_params` value and `framework` tag.
2. For each case, exactly one log line with that request's `jti`. It must have exactly the CONTRACT field set and types, with `op_id`, `status`, `raw_method`, `effective_method`, `raw_target` (byte-exact), `query`, `route_template`, `path_params` and `denied` matching.
3. Trust-header capture: 5 trust headers are captured, lower-cased and exact, and `X-Unrelated` is not captured.
4. `jti: null` when the request has no DPoP header.

Probes use an **unsigned** fake DPoP proof. Executors must read `jti` without verifying it.

## Contract interpretations (apply to all W4 executors; recommended for W5)
1. **Method mismatch is NOT_FOUND.** §3 says "any unmatched request gets 404 NOT_FOUND". A known path with a wrong method is treated as unmatched, and the framework's 405 is converted to 404.
2. **Framework-native responses are kept and logged.** These include redirects (FastAPI's 307 trailing-slash redirect), automatic HEAD→GET, Django's automatic `OPTIONS` 200, and so on. They are logged with whatever `op_id` the handler set. If no bench handler ran, the log says `op_id: "NOT_FOUND"` and `route_template: null`, with the real status (e.g. 307 or 200). Path normalisation is the object of study (G2), so we do not override framework defaults. These lines are never oracle hits, because `op_id` is NOT_FOUND.
3. **Requests rejected by the HTTP server before the framework runs produce no log line.** Examples are a lower-case method under Node or gunicorn (400), and malformed request lines. The oracle should treat "no executor line for this jti" as "not executed".
4. **Verification point.** In `origin-*` modes the verifier is called after routing and dispatch have chosen the op, but before the response is produced. NOT_FOUND requests are not sent to the verifier, because there is no operation to protect. Denied requests return 401 with body `{"op_id","framework","denied":true}` and are logged with the op that *would* have run.
5. **Fail closed.** If the verifier is unreachable or times out (3 s), the request is denied.
6. **`origin-routed` URI encoding.** `X-Original-URI` is the route template with each path parameter substituted as follows: take the framework's value (percent-decoded first if the framework returned it raw, as chi does), then percent-encode it with RFC 3986 unreserved characters plus sub-delims, `:` and `@` left literal. This matches Python `quote(v, safe="-._~!$&'()*+,;=:@")`. A decoded `/` inside a parameter is therefore re-encoded as `%2F`. There is no query.
7. **`origin-raw` method.** `X-Original-Method` is the raw method from the request line, before override.
8. **`path_params` in the log and response** are the values *as the framework extracted them*, which may be decoded or raw depending on the framework. They are deliberately not normalised, because this difference is a measured G2 property.
9. **Duplicate trust headers** are joined in arrival order. The joiner is `", "` in every server except gunicorn/WSGI, which joins with `","` before the app sees the headers. Header names that need lossy mapping are recorded as the server exposes them. For example, under WSGI an underscore header is dropped by gunicorn by default.
10. **`raw_target`** is the request target as the server reports it: uvicorn `raw_path`+`?`+`query_string`, Node `req.url`, gunicorn `RAW_URI`, Go `r.RequestURI`. For origin-form requests this is byte-exact. The conformance test asserts it.
11. **Dispatch defaults.** For `op`, anything other than exactly `freeze` or `close`, including an array produced by a framework's query parser, gives `accountAction.unknown`. For `operationName`, anything other than exactly `getProfile` or `deleteProfile`, a non-object body, or invalid JSON gives `graphql.unknown`.
12. **OpenAPI and multiple op_ids.** OpenAPI allows one `operationId` per operation. The two dispatching operations therefore carry the family name (`accountAction`, `graphql`) as `operationId`, and list the concrete logged op_ids in `x-bench-dispatch`.

## Known limitations
- The `VERIFY_MODE` checks use the stub, not W3's real verifier. They test the executor's side of the interface (which view it sends and how it handles allow/deny), not DPoP verification.
- Override probes are informational, so the script does not decide whether a framework's override behaviour is "correct".
- `--docker-logs` needs the container's stdout. If stdout also carries non-JSON lines, those lines are ignored.
