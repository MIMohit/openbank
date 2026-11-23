# Defences D-A, D-B, D-C (W11)

This directory holds the executor-side check for **D-B, the view-binding MAC** (CONTRACT §8 and §10). It contains:
- one implementation for each of FastAPI, Express, Spring and ASP.NET Core;
- a shared test-vector file generated from the reference verifier;
- patches that wire the check into the four bench executors behind `DEFENCE=db`;
- an end-to-end check of the patched executors against the real verifier;
- design notes for D-A, D-B and D-C, and their coverage against G1, G2 and G3.

Nothing in `harness/executors/`, `harness/orchestrator/` or `harness/verifier/` was modified. The integration is delivered as patch files in `patches/`, for the coordinator to apply.

## 1. Design

The paper's binding-soundness property: if the verifier accepts a proof π for its view v(r) = (method, URI), the backend must execute op(π). The three defences close the gap between the verifier's view and the executor's view in three different ways.

### D-A: origin-routed verification (already in all 8 executors)
`VERIFY_MODE=origin-routed` moves the verification decision to the executor, after routing. The executor sends the verifier the method it actually dispatched on (after override resolution) and the canonical path of the route it matched (template plus substituted parameters, no query). The verifier then runs the normal RFC 9449 htm/htu checks against that routed view. There is no view to trust and no header to propagate, because the executor asks about exactly what it is about to execute.

Costs and caveats:
- The executor needs a network call to the verifier on every request, unless the verifier is embedded as a library.
- There is a canonicalisation seam. The executor re-encodes decoded parameters with the D-A encoder: unreserved characters, sub-delims, `:` and `@` stay literal, and everything else is percent-encoded. The verifier then applies RFC 3986 normalisation, including `remove_dot_segments`. A decoded parameter equal to `.` or `..` therefore collapses.
  - Example: Express routes `GET /api/v1/public/%2E%2E` to `publicFile` with `file=".."` (observed in-process in `express/test`). Under D-A the executor reports `/api/v1/public/..`, and the verifier canonicalises that to `/api/v1/`.
  - A proof for `htu=…/api/v1/` would therefore authorise `publicFile("..")`.
  - This was not measured in the harness. It is low impact here, because no bench operation lives at `/api/v1/`, but it is a real soundness gap in D-A.
  - The D-B check below rejects such parameters (`view_param_dot_segment`). D-A should do the same.

### D-B: view-binding MAC (this directory)
D-B is for the edge placement. The gateway calls the verifier, and the verifier returns its view on allow, MAC'd under a key it shares with the executor:
```
X-Verified-View: v1;b64url(HMAC-SHA256(K, jti "\n" UPPER(view_method) "\n" canon_path(view_uri) "\n" jkt))
```
Here `canon_path` is the RFC 3986-normalised path only (§10): query and fragment are dropped, percent-encoded unreserved characters are decoded, hex is upper-cased and `remove_dot_segments` is applied. `%2F` is not decoded and `//` is not collapsed. The gateway forwards the header upstream; all six W6 gateways already copy `X-Verified-*` (gateways/README.md).

The executor recomputes the MAC over **its own view**:
- **method:** the effective method after the framework's method override;
- **path:** the matched route template, with decoded parameters substituted using the same encoder as D-A, then `canon_path`;
- **jti:** read from the DPoP proof payload, and **jkt** as the RFC 7638 thumbprint of the proof header's `jwk`. Both are parsed without verifying the signature; the verifier already did that. Swapping the proof or the key changes jti or jkt, and the MAC then fails.

The request is rejected with **401** (`WWW-Authenticate: DPoP error="invalid_token"`, body reason below) unless all of the following hold:

| order | condition | reason on failure |
|---|---|---|
| 1 | exactly one `X-Verified-View` value (a duplicate is the G3 injection pattern) | `view_mac_missing`, `view_mac_multiple` |
| 2 | value matches `^v1;[A-Za-z0-9_-]{43}$` after trimming OWS | `view_mac_malformed` |
| 3 | exactly one `DPoP` header, a 3-part JWS with a string `jti` and an EC, RSA or OKP `jwk` | `view_mac_no_dpop` |
| 4 | no path parameter equals `.` or `..` | `view_param_dot_segment` |
| 5 | constant-time equal to the recomputed MAC | `view_mac_mismatch` |

The comparisons use `hmac.compare_digest`, `crypto.timingSafeEqual` (after a length check; lengths are public, fixed at 46), `MessageDigest.isEqual` and `CryptographicOperations.FixedTimeEquals`. An empty key refuses to start.

The check runs after routing and override, and before the handler has any side effect. In the patches it sits at the same choke point D-A uses, before the D-A call: `respond()`, `Bench.enter()` and `Op()`. That way the log line still carries the matched `op_id` with `"denied": true`. Each implementation also ships a framework-native adapter:
- a FastAPI dependency;
- an Express route-level middleware;
- a Spring `HandlerInterceptor`;
- an ASP.NET Core middleware placed after `UseRouting()`.

These adapters are tested but not used by the patches.

What D-B does *not* do is make the executor's view correct. It makes *any* disagreement between the two views fail closed. Mismatches caused by benign canonical-form differences become false rejects, never bypasses. One example is ASP.NET leaving `%2F` encoded inside a route value (tested: `EncodedSlashParamFailsClosed`).

### D-C: strict canonical edge
This is verifier `HTU_CANON=strict` plus the gateway `strict` profile (W6). Ambiguous request targets are refused at the edge, before any differential can arise. On the verifier side these are dot-segments (raw or `%2E`), `//`, `%2F`, `%5C`, `\`, `%00`, `%25`, `;`, encoded unreserved characters, lower-case hex, malformed `%` and non-ASCII. The gateway side rejects escaped slashes, merges slashes, and so on, per gateway. D-C needs no executor change. It is input hygiene, though, not a binding: a canonical target can still be routed differently from how it was verified. Case-insensitive or trailing-slash-tolerant routers are examples, and so is method override.

### Threat coverage
✔ = closed by construction. ✘ = not addressed. ◐ = partial. "Tested" points at evidence in this directory; everything else is analytical.

| failure (class) | D-A origin-routed | D-B view MAC | D-C strict edge |
|---|---|---|---|
| method override via header or `_method` (G1) | ✔ the verifier sees the effective method | ✔ mismatch, 401 (tested e2e, all 4 fw) | ✘ the override is invisible to a URI check (a gateway could strip the header, but not a body `_method`) |
| query dispatch, `?op=` (G1) | ✘ the query is outside htu | ✘ the MAC is path-only, by §10 (tested e2e: `g1_query_dispatch` → 200 `accountAction.close`) | ✘ |
| body dispatch, GraphQL `operationName` (G1) | ✘ | ✘ | ✘ |
| path differentials: dot-segments, encoded slash, `;`, case, trailing slash, prefix mount (G2) | ✔ except the `..`-parameter seam above | ✔ fail closed (vectors `g2_*`) | ◐ refuses non-canonical input; case and trailing-slash differentials remain |
| different `{id}` or owner (G2) | ✔ | ✔ (tested e2e: `header_lifted_to_other_id`) | ◐ |
| spoofed or duplicated trust header, verifier bypass (G3) | ✔ the executor trusts no header | ✔ for the view itself: a forged MAC fails without K, a duplicate is rejected, a missing header gets 401 (tested e2e). ✘ for `X-Verified-Sub` and `-Jkt`, which are not covered by the MAC | ✘ |
| direct-to-executor replay of a captured, gateway-verified request | ✔ the verifier's jti cache | ◐ only the identical (jti, method, path) can be replayed, and the executor keeps no jti cache | ✘ |

G1 query and body dispatch need a binding over more of the request: the query, or a content digest. Possible routes are RFC 9421 or an extended MAC input. That is outside the §8 MAC format.

### Ingress stripping requirement
The gateway must delete client-supplied `X-Verified-*` (and `X-Original-*` / `X-Forwarded-*`) headers at ingress, before it adds the verifier's. For the view itself, D-B stays sound without stripping:
- a client copy plus the gateway copy gives `view_mac_multiple`;
- a client copy alone, when the gateway did not propagate one, gives `view_mac_mismatch`.

So stripping is needed for availability and for the headers the MAC does not cover. Any backend logic that reads `X-Verified-Sub` or `X-Verified-Jkt` is exposed to G3 unless they are stripped, or folded into a `v2` MAC input. The bench executors read neither.

### Key management
- `VIEW_MAC_KEY` is a shared symmetric key between the verifier and the executors. The key is the UTF-8 bytes of the env string. Use at least 32 random bytes, for example `openssl rand -base64 32`, and deliver it via a secret store or a docker secret, not baked into images. The harness uses fixed test keys.
- Any holder of K can mint views, so K must never reach the gateway or the client. The gateway only forwards the header.
- **Rotation** is not implemented. A deployment would accept {K_current, K_next} on the executor during a window, and add a key id (e.g. `v1;kid;mac`). That is a format change for the coordinator.
- Scope K per verifier and executor trust domain. A key shared across tenants lets one domain's verifier mint views for another domain's executors.

## 2. Files
| path | what |
|---|---|
| `vectors.json` | Shared test vectors: 19 canon_path, 4 thumbprint (EC ×2, RSA, OKP), 4 mac, 9 substitute, 32 check cases (14 ok, 18 reject) |
| `vectors/gen_vectors.py` | Generates the vectors using `verifier.core.view_mac`, `verifier.canon.canon_path` and `verifier.jose.thumbprint`. It imports nothing from the four implementations. The proof keys are random, so a re-run produces a different but equivalent file. |
| `fastapi/viewmac.py`, `fastapi/tests/` | Python (stdlib only) core `check()`, plus the `fastapi_dependency(key)` adapter; pytest |
| `express/viewmac.js`, `express/test/` | Node core `check()`, plus the `viewMac(key)` route-level middleware; node:test |
| `spring/src/main/java/bench/defence/{ViewMac,ViewMacInterceptor}.java`, `spring/src/test/` | Java core, plus the `HandlerInterceptor`; JUnit 5 + Spring Boot MockMvc |
| `aspnet/ViewMac/{ViewMac,ViewMacMiddleware}.cs`, `aspnet/ViewMac.Tests/` | C# core, plus the `UseViewMac(key)` middleware; xUnit + TestHost |
| `patches/<fw>-defence-db.patch` | Executor integration (fastapi, express, spring, aspnet) |
| `patches/make_patches.py` | Regenerates the four executor patches from the current executor sources (asserts each anchor is unique) |
| `patches/orchestrator-defence-db.patch` | Suggested W6 change: topology key `defence: off\|db` → executor `DEFENCE` + `VIEW_MAC_KEY` |
| `e2e/e2e_client.py`, `e2e/run_e2e.sh`, `e2e/results/` | End-to-end run of patched images against `bh-verifier:latest`: raw JSON results and executor/verifier logs |

## 3. Applying the patches (coordinator, after W9)
```sh
cd binding/harness
python3 defence/patches/make_patches.py          # optional: regenerate against the current executors
for fw in fastapi express spring aspnet; do patch -p1 < defence/patches/$fw-defence-db.patch; done
patch -p1 < defence/patches/orchestrator-defence-db.patch   # W6-owned: suggestion only
# rebuild bh-exec-{fastapi,express,spring,aspnet}:latest; then in a topology:
#   verifier: {view_mac: on, view_mac_key: ...}   defence: db   placement: edge
```
Each patch:
- copies the D-B module into the executor directory (`viewmac.py`, `viewmac.js`, `src/main/java/bench/defence/ViewMac.java`, `ViewMac.cs`);
- adds it to the Dockerfile `COPY` where needed;
- reads `DEFENCE=off|db` (default `off`, so behaviour is unchanged) and `VIEW_MAC_KEY`, and exits at startup for a bad value or a missing key;
- runs the check first at the operation choke point. On failure it logs `denied: true` with the matched `op_id`, and returns 401 with `{"op_id", "framework", "denied": true, "reason"}`.

The CONTRACT log schema is unchanged; the reason appears only in the response body. D-B composes with `VERIFY_MODE` (the check runs first) and with `OVERRIDE`. The patches touch only fastapi, express, spring and aspnet. django, go-chi, rails and laravel would need the same few lines plus a port of the module, which was not done.

`patch -p1 --dry-run` succeeds for all five patches against the executor and orchestrator sources as of 2026-11-23. Patches regenerated by `make_patches.py` were byte-identical, apart from the `---`/`+++` timestamp lines, to the ones built into the e2e images.

## 4. Running the tests
```sh
cd binding/harness/defence
# Python 3.12
python3.12 -m venv fastapi/.venv && fastapi/.venv/bin/pip install -r fastapi/requirements-dev.txt
fastapi/.venv/bin/python -m pytest -q fastapi/tests
# Node
(cd express && npm install && node --test test/)
# Java (no local JDK needed)
docker run --rm --name w11-spring-test -v w11-m2:/root/.m2 -v "$PWD":/defence -w /defence/spring \
  maven:3.10.0-eclipse-temurin-21 mvn -B test -Dvectors=/defence/vectors.json
# C#
docker run --rm --name w11-aspnet-test -v w11-nuget:/root/.nuget -v "$PWD":/defence -w /defence/aspnet \
  -e VECTORS=/defence/vectors.json mcr.microsoft.com/dotnet/sdk:9.0.321 dotnet test ViewMac.Tests/ViewMac.Tests.csproj
# regenerate vectors (from binding/harness)
PYTHONPATH=. verifier/.venv/bin/python defence/vectors/gen_vectors.py > defence/vectors.json
# end to end (from binding/harness; needs w11-exec-<fw>:db built from a patched copy of the executor)
defence/e2e/run_e2e.sh <fw>
```

## 5. Results (2026-11-23, macOS arm64)
Unit tests. Every language passes all vector groups: canon_path 19/19, thumbprint 4/4, mac 4/4, substitute 9/9, check 32/32.

| impl | runtime | result |
|---|---|---|
| Python | 3.12.13, fastapi 0.165.0, starlette 1.10.0, pytest 8.3.5 | **75 passed**: 68 vectors, the empty-key test, a 20 000-input random differential of `canon_path` against `verifier.canon.canon_path`, and 5 FastAPI adapter tests |
| Node | 26.13.1, express 4.22.3, method-override 3.0.0 | **38 passed** (4 vector-group tests, 32 check cases, empty key, Express adapter) |
| Java | Temurin 21.0.13 (maven:3.10.0-eclipse-temurin-21), Spring Boot 3.5.16 | **76 passed** (70 vector tests and template normalisation, plus 6 interceptor tests including `addPathPrefix` and `HiddenHttpMethodFilter`) |
| C# | .NET SDK 9.0.321, xUnit 2.9.2, TestHost 9.0.0 | **76 passed** (69 vector tests, plus 7 middleware tests including `MapGroup`, `{n:int}` and both `UseHttpMethodOverride` sources) |

Framework behaviours the adapter tests observed:
- Starlette routes on the decoded path, so `/api/v1/public/a%2Fb` gives 404 before the check.
- Express decodes `%2F` into the parameter, and the check re-encodes it, so it matches.
- ASP.NET keeps `%2F` encoded in route values, so the request fails closed: a false reject, not a bypass.
- Spring's `TestTypeExcludeFilter` hides nested test controllers, which is why the interceptor test uses `@Import`. The interceptor ignores non-`HandlerMethod` handlers, so unmatched requests still get 404.

**End to end**, raw output in `e2e/results/<fw>.json`. For each framework the setup was:
- the patched image `w11-exec-<fw>:db`, built from a scratch copy plus the patch;
- `bh-verifier:latest` with `VIEW_MAC=on`, with the gateway emulated by calling `/authz/orig`;
- executors with `OVERRIDE=on` and `VERIFY_MODE=off`, one with `DEFENCE=db` and a control with `DEFENCE=off`.

All 7 cases gave the same results on all four frameworks:

| case | verifier | DEFENCE=db | DEFENCE=off (control) |
|---|---|---|---|
| benign GET | allow | 200 getAccount | 200 getAccount |
| benign `/api/v2` prefix mount | allow | 200 getAccountV2 | 200 getAccountV2 |
| G1 method override (POST verified, DELETE dispatched) | allow | **401** `view_mac_mismatch` (op deleteAccount, denied) | 200 **deleteAccount** |
| G1 query dispatch (`op=freeze` verified, `op=close` sent) | allow | 200 **accountAction.close** (not covered) | 200 accountAction.close |
| view header lifted to `acc-bob-1` | allow | **401** `view_mac_mismatch` | 200 getAccount (bob) |
| no `X-Verified-View` | allow | **401** `view_mac_missing` | 200 me |
| duplicated `X-Verified-View` | allow | **401** `view_mac_multiple` | 200 me |

For the `DEFENCE=db` denials, the executor JSONL logs (`e2e/results/logs-<fw>/db/executor.jsonl`) show `denied: true` with the matched `op_id`, `effective_method` and `jti`. Image ids are in `e2e/results/<fw>.image.txt`. All w11 containers and networks were removed afterwards.

## 6. Known limitations
- The MAC covers neither the query nor the body, by §10. D-B leaves G1 query and body dispatch open; this is shown, not assumed (`g1_query_dispatch`).
- `X-Verified-Sub` and `X-Verified-Jkt` are not MAC'd.
- There is no executor-side jti cache and no key rotation or key id.
- False rejects arise wherever a framework's route-value decoding differs from the verifier's canonical form. ASP.NET `%2F` is one; others are untested: Spring's semicolon stripping (`g2_semicolon_param` is a vector-level case only), and case-insensitive or trailing-slash routing.
- Patches exist only for 4 of the 8 executors.
- The e2e run emulates the gateway; it was not run through the orchestrator or W6 gateways, because that needs the orchestrator patch.
- Thumbprints in the Node, Java and C# implementations accept only JWK members that need no JSON escaping. Valid EC, RSA and OKP keys always qualify; anything else fails closed as `view_mac_no_dpop`.
