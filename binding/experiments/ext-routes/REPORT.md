# Extension round W15: richer route space (v2 images)

Worker **w15**. Addresses G1_REPORT §6 item 1: enlarge the bench route space so that the
structural levers the depth-1 corpus already carries (method override, fragment keeping, dot-segment
disagreement) can turn into **operation** changes instead of staying latent.

Four v2-only routes were added to all eight executors behind `ROUTES=v2` (default off, so `:latest`
behaviour is unchanged):

| op_id | method | path | purpose (G1_REPORT §6) |
|---|---|---|---|
| `postAccount` | POST | `/api/v1/accounts/{id}` | shares a path with GET/PUT/DELETE → exercises the **POST-only override** middleware |
| `getStatements` | GET | `/api/v1/accounts/{id}/statements` | **nested same-method route** → turns RC6 (`#`) into a route change |
| `deleteStatement` | DELETE | `/api/v1/accounts/{id}/statements/{sid}` | deeper nested route |
| `catchAllFile` | GET | `/api/v1/files/{path:path}` | **catch-all** → turns latent L1 (dot segments) into an executed op |

Images `bh-exec-<fw>:v2` were built one at a time; `:latest` was never overwritten. The OpenAPI spec
was extended as `bench-api.v2.openapi.yaml` and conformance as `conformance/run_conformance.py --v2`.

**Data.** 32 topologies × 581 depth-1 cases = **18,592 raw requests**, all real components
(`orchestrator.up --stubs off`), run 2026‑11‑23. Gateways **nginx 1.30.7-alpine** and **envoy v1.39.6**,
both **default** profile, placement edge. Verifier `bh-verifier:latest` (HTU_CANON=rfc3986). Executors
`bh-exec-{fastapi,express,django,go-chi,spring,aspnet,rails,laravel}:v2`. Matrix = 2 gateways × 8
frameworks × override {off,on} = 32. Every number below is traceable to `runs/<id>/{hits,verifier,
executor,runner}.jsonl`, `runs/summary.csv`, `reruns/<id>/rerun_outcome.jsonl`, `ddmin/*.json` and
`analysis/*.csv`.

Conformance: all 8 frameworks pass `run_conformance.py --v2` in every one of the 6
`OVERRIDE × VERIFY_MODE` configurations (48/48 config blocks, 0 failures; `conformance-out/matrix.log`).
Ground truth for all 16 `(framework, override)` pairs is conformant (`groundtruth/*.jsonl`): every base
op, including `postAccount`/`getStatements`/`deleteStatement`/`catchAllFile`, returns its own op_id.

---

## 0. Verdict

| criterion (CONTRACT §12 hard-kill) | result |
|---|---|
| ≥ 2 **independent G2/G3 classes** with binding resolution > 1 (or a G2/G3 authz-soundness violation) on current releases, default/documented config | **MET — 2 independent G2 classes.** (1) **Fragment nested-route substitution** (nginx forwards raw `#`; fastapi/go-chi/laravel keep it in the path; the RFC 3986 verifier drops it): a leaked `getAccount` proof executes **`getStatements`**, and a leaked `deleteAccount` proof executes **`deleteStatement`** (S1) — a genuine *operation*-binding break, default profile, override **off**. (2) **Dot-segment differential realised by the catch-all** (`{path:path}` keeps `./`/`%2e` that the verifier removes per RFC 3986 §6.2.2.3): `catchAllFile` executes with a non-covered path, on **both** gateways, 7/8 frameworks, override off. Class (2) is **real but practically low** (only no-op `./` passes; every `..` traversal is denied by the verifier). **G3: 0 binding classes.** |
| POST-only override reachable in ≥ 2 frameworks' documented config | **MET, strongly.** With the shared `POST /accounts/{id}` route, the standard method-override middleware turns a leaked `postAccount` proof into **PUT/DELETE** (`updateAccount`/`deleteAccount`, S1) in **all 8 frameworks** under `OVERRIDE=on`. For **Rails** (full non-`api_only` stack: `Rack::MethodOverride` is in the **default** middleware) and **Laravel** (Symfony `_method` form override, on by default) this middleware is part of the **default** configuration. This is G1 (method not covered by the proof), not G2/G3, but it removes W9's "trivial clause (b)" caveat: operation-binding under method override is now default-reachable, not a FastAPI-only transliteration. |

**Recommendation.** The richer route space converts two of W9's "latent / practically-low" observations
into real operation-binding breaks. The strongest single result is **G2 class (1)**: on a **default**
nginx + fastapi/go-chi/laravel stack, a proof that a verifier accepts for one operation executes a
*different, adjacent* operation, including the state-changing `deleteAccount → deleteStatement`. This is
the first result in the project where an **interpretation differential (G2)** — not application dispatch
(G1) — produces an operation change under a documented, default configuration. Combined with the
all-eight-frameworks POST-override G1 result, the evidence now supports the operation-binding thesis
beyond a measurement paper, subject to the honest caveats in §5.

---

## 1. Headline numbers

| | value |
|---|---|
| cases sent / transport errors | 18,592 / 0 |
| verifier-accepted | 12,680 |
| raw hits | **226** |
| by class | **G1: 116** (method override), **G2: 110** (56 dot-segment catch-all + 42 fragment resource-suffix + 12 fragment nested-route), **G3: 0** |
| confirmed 3/3 on fresh topologies | **226 / 226** (0 flaky, 0 irreproducible) |
| unique signatures | 34 |
| independent **G2/G3** classes | **2** (both G2); G3 binding classes 0 |
| B0 verifier bypass | 0 |
| G3 propagation findings (separate predicate) | 1,952 total; all are gateway-overwritten `x-verified-*`/`x-forwarded-*` echoes — the same artefact W9 flagged (§5), **0** independent G3 binding classes |
| uncorrelated executor records (`jti=null`) | 170 (orchestrator `/health` probes) |
| nonconformant ground truth | 0 |

## 2. Hits per gateway × framework × override (G1 / G2)

Source `analysis/hits_per_topology.csv`. Cell = hits (g1/g2); G3 is 0 throughout. Both gateways are
**default** profile.

| framework | nginx off | nginx on | envoy off | envoy on |
|---|---|---|---|---|
| fastapi | 11 (0/11) | 23 (12/11) | 2 (0/2) | 14 (12/2) |
| go-chi  | 11 (0/11) | 17 (6/11) | 2 (0/2) | 8 (6/2) |
| laravel | 11 (0/11) | 20 (9/11) | 2 (0/2) | 11 (9/2) |
| express | 2 (0/2) | 11 (9/2) | 2 (0/2) | 11 (9/2) |
| django  | 2 (0/2) | 8 (6/2) | 2 (0/2) | 8 (6/2) |
| spring  | 2 (0/2) | 6 (4/2) | 2 (0/2) | 6 (4/2) |
| rails   | 2 (0/2) | 8 (6/2) | 2 (0/2) | 8 (6/2) |
| aspnet  | 0 | 6 (6/0) | 0 | 6 (6/0) |

Observations:
- **Gateway splits the two G2 classes.** The 11-vs-2 gap on fastapi/go-chi/laravel is exactly the
  fragment class (9 extra G2 hits): **nginx forwards the raw `#`**, **envoy's default `normalize_path`
  rejects / strips it**, so the fragment family only lands behind nginx. The residual **2 G2 hits on
  every (gateway, framework≠aspnet) cell** are the dot-segment catch-all class, which is gateway-
  independent (neither gateway removes `./`).
- **aspnet has 0 G2.** ASP.NET Core's routing normalises `./` and does not keep `#`, so neither G2 class
  reaches its handlers. (Its override-on G1 hits are present.)
- **Override on adds G1 only.** The method-override hits (POST→PUT/DELETE and the FastAPI any-method
  header) are the entire off→on delta and are identical across the two gateways.

## 3. Distinct root causes

| RC | class | mechanism (verifier view vs. executor dispatch) | where | default profile | severity | new vs W9 |
|---|---|---|---|---|---|---|
| **X1** | **G2** | nginx forwards raw `#…`; fastapi(uvicorn/h11), go-chi(net/http), laravel(FrankenPHP) keep `#` in the path; RFC 3986 verifier drops the fragment → binds the base op. **Nested route catches the suffix** → different op | nginx × {fastapi,go-chi,laravel}, ov off+on (6 topos) | yes | **S1** `deleteAccount→deleteStatement`, **S2** `getAccount→getStatements` | **NEW — operation change.** W9 RC6 was only an id suffix |
| X2 | G2 | same `#` mechanism, **no nested route** → same op, `{id}`/`{sid}`/`file` gets `#frag` suffix | nginx × {fastapi,go-chi,laravel}, 7 ops | yes | S1 (resource), **practically low** | = W9 RC6, extended to v2 ops |
| **X3** | **G2** | RFC 3986 verifier removes `./` / `%2e` (§6.2.2.3) and binds the canonical htu; gateway forwards raw; **catch-all `{path:path}` keeps the raw segment** → non-covered path | both gw × {7 fw, not aspnet}, ov off+on | yes | S1 (resource), **practically low** | **NEW realisation** of W9 §5 L1 (which 404'd); now executed |
| X4 | **G1** (method override) | leaked `postAccount` (POST) proof; override middleware rewrites POST→PUT/DELETE/GET → routes to the shared-path sibling op | all 8 fw, `OVERRIDE=on`; **Rails/Laravel default-on** | n/a (framework) | S1 (`updateAccount`/`deleteAccount`) | **NEW — all 8 fw.** W9 RC5 was FastAPI-only |
| X5 | G1 (method override) | FastAPI `HTTPMethodOverrideASGI` honours `X-HTTP-Method-Override` on **any** base method (Flask pattern) | fastapi × `OVERRIDE=on` | n/a | S1 | = W9 RC5 |

**Independent topology classes (oracle_spec §9 item 3).**
- **G2: 2 classes.** **Class (1) = X1 ∪ X2** — one fragment-handling differential (shared gateway nginx,
  shared `#` mechanism, shared framework set); X1 is its high-impact realisation (operation change), X2
  its low-impact one (id suffix). **Class (2) = X3** — the dot-segment/catch-all differential, a different
  component (verifier dot-segment removal vs. catch-all raw capture), different gateways and framework set.
- **G1: 1 class** — method override (X4 ∪ X5), now default-reachable (Rails/Laravel) and present in all 8
  frameworks when enabled.
- **G3: 0 classes.**

## 4. Resolution distribution (`analysis/resolution.csv`)

`res_hat` per (topology, base op), 32 × 8 = 256 pairs: **1: 176, 2: 40, 3: 19, 4: 16, 5: 3, 6: 2.**

| base op | max res_hat | cause |
|---|---|---|
| postAccount | **5** | X4 (POST→get/put/delete via override) + X2 (`#`) — the shared-path POST is the richest |
| getAccount / updateAccount / deleteAccount | **6** | X4 (override) + X1 (nested route) + X2 (`#`) |
| deleteStatement / publicFile | 2 | X2 (`#`) |
| catchAllFile | 4 | X3 (`./`, `%2e` variants) |
| getStatements | 1 | none (it is the *target* of X1, never a substitutable source) |

## 5. Skepticism: harness artefacts and honest severity

1. **G2 class (1) is a real operation change, not a suffix.** The verifier logs `decision=allow` with the
   fragment still in the raw `view_uri` but canonicalises it away for the match (RFC 9449 §4.3), binding
   `getAccount`/`deleteAccount`; the executor routes to `getStatements`/`deleteStatement` with a *different
   `op_id` and route_template* (`runs/w15r-nginx-default-edge-fastapi-ovoff`). The substituted `{id}` is the
   mangled `acc-alice-1#`, so the attacker cannot choose the target resource — but the **operation** that
   runs is not the one the proof authorised, which is the binding-soundness claim. ddmin reduces each to a
   single appended `#/statements[/s-evil]` on the target (`ddmin/*x-frag*`).
2. **G2 class (2) is genuine but practically low.** Only the **no-op** dot segment passes: `./` and `%2e/`
   canonicalise to the htu so the verifier allows, while the catch-all keeps the literal. **Every traversal
   that could reach another resource is denied by the verifier**: `..`, `%2e%2e`, `%2f`, `//`, matrix params,
   trailing slash and backslash all give `htu_mismatch` deny (`runs/.../fastapi-ovoff`, §probe). So X3
   realises W9's latent L1 as an *executed* request, but cannot reach a different file, route, or owner. It
   is reported as a class because it is a distinct, reproducible verifier/router differential with res > 1,
   not because it is dangerous.
3. **X2 severity is inflated by the oracle rule** (as W9 RC6): "same op, different `path_params`" is S1, but
   the id differs only by a `#…` suffix; no other resource is reachable.
4. **The oracle labels the custom fragment primitive `x-frag-*` as class `"x"`**, because it derives class
   from the primitive-id prefix (`pid.split("-")[0]`) and does not load W15's custom primitives. These hits
   are G2 by mechanism (RFC 3986 fragment differential); `scripts/analyse.py` remaps `x → g2` for
   aggregation and the raw `runs/*/hits.jsonl` keep the oracle's literal label for traceability.
5. **G3 is propagation-only.** The 1,952 propagation findings are all gateway-overwritten `x-verified-*` /
   `x-forwarded-*` echoes — the W9 §5 false-positive pattern (marker equals the value the gateway sets).
   No G3 case changed an op. **0 G3 binding classes.**
6. **Clock skew.** The Docker VM clock was checked before every rerun rep (`ext_rerun.clock_check`, 5 s
   tolerance; the W9 §5 host-sleep hazard). No rerun shows an `iat_skew` deny.
7. **Method override is G1, not G2.** X4/X5 change the *method*, which the proof's `htm` is supposed to bind
   but which the override rewrites **after** the verifier's view is taken (edge placement, raw view). This is
   under-binding by design (CONTRACT §7 G1). It is reported for completeness and because it is the task's
   explicit "POST-proof → PUT/DELETE" deliverable, but it is **not** counted toward the G2/G3 class total.

## 6. Task deliverables

### POST-proof → PUT/DELETE executed via override (X4)
With `OVERRIDE=on` a leaked `postAccount` (POST `/accounts/{id}`) proof executes a **different method's**
sibling op. Vectors that fired, per framework (`analysis/hits_all.jsonl`, base `postAccount`, override on):

| framework | override middleware (README/source) | vectors POST→X | reached ops |
|---|---|---|---|
| express | `method-override@3.0.0` | form `_method`, `X-HTTP-Method-Override`, `X-HTTP-Method`, `?_method` | get/update/deleteAccount |
| laravel | Symfony `_method` form override (**default**) + header | form `_method`, `X-HTTP-Method-Override`, `X-HTTP-Method`, `?_method` | get/update/deleteAccount |
| rails | `Rack::MethodOverride` (**default** full stack) | form `_method`, `X-HTTP-Method-Override`, `X-HTTP-Method` | get/update/deleteAccount |
| aspnet | `UseHttpMethodOverride` | form `_method`, `X-HTTP-Method-Override`, `X-HTTP-Method` | get/update/deleteAccount |
| django | `django-method-override 1.0.4` | form `_method`, `X-HTTP-Method-Override`, `X-HTTP-Method` | get/update/deleteAccount |
| go-chi | gorilla `handlers.HTTPMethodOverrideHandler` | form `_method`, `X-HTTP-Method-Override`, `X-HTTP-Method`, `?_method` | update/deleteAccount |
| spring | `HiddenHttpMethodFilter` | form `_method`, `?_method` | update/deleteAccount |
| fastapi | `HTTPMethodOverrideASGI` (Flask pattern, any base method) | `X-HTTP-Method-Override`, `X-HTTP-Method` | get/update/deleteAccount |

- **Default vs opt-in.** In the harness `OVERRIDE` is a toggle. In real deployments the middleware ships
  **on by default** for **Rails** (non-`api_only` apps) and **Laravel** (form `_method`), making X4 a
  *default-config* G1 for those two; it is opt-in for the other six.
- **S1.** `deleteAccount`/`updateAccount` are state-changing; a POST authorisation becomes a DELETE/PUT.

### Catch-all path effects (X3)
`GET /api/v1/files/{path:path}` with a no-op dot segment executes `catchAllFile` on a path the proof never
covered (verifier binds `/files/reports/logo.png`, executor captures `reports/./logo.png`). Only no-op
segments pass; traversal is denied (§5.2). Practically low, but a clean verifier/router differential on
both gateways and 7/8 frameworks, default profile, override off.

### Nested-route substitution (X1) — the headline G2 result
`GET /accounts/{id}#/statements` → verifier allows `getAccount`, executor runs **`getStatements`**;
`DELETE /accounts/{id}#/statements/s-evil` → verifier allows `deleteAccount`, executor runs
**`deleteStatement`**. nginx × {fastapi, go-chi, laravel}, default profile, override off **and** on.

## 7. Determinism (oracle_spec §10)

Every one of the 226 hits was re-run 3× on a freshly started topology (`down`→`up --fresh-logs`), fresh
proof per send, via `scripts/ext_rerun.py`. Result: **226/226 confirmed (3/3)**, 0 flaky, 0 irreproducible.
Per-topology outcomes in `reruns/<id>/rerun_outcome.jsonl`.

## 8. Minimisation (ddmin, `ddmin/*.json`)

Each distinct root cause was ddmin-minimised against a live topology (`scripts/ext_ddmin.py`, oracle
`minimise.ddmin` over target/header/body/method units):
| RC | case (base → exec) | sev | units (full→min) | minimal delta (the single lever that remains) |
|---|---|---|---|---|
| X1 | `getAccount` → **`getStatements`** | S2 | 12→12 | request-target suffix `#/statements` on `GET /api/v1/accounts/acc-alice-1` |
| X1 | `deleteAccount` → **`deleteStatement`** | S1 | 19→19 | request-target suffix `#/statements/s-evil` on `DELETE /api/v1/accounts/acc-alice-1` |
| X2 | `getAccount` → `getAccount` (id suffix) | S1\* | 5→5 | request-target suffix `#frag` |
| X3 | `catchAllFile` → `catchAllFile` (`./`) | S1\* | 2→2 | one literal `./` segment in `GET /api/v1/files/reports/./logo.png` |
| X3 | `catchAllFile` → `catchAllFile` (`%2e`) | S1\* | 4→4 | one encoded `%2e/` segment |
| X4 | `postAccount` → **`deleteAccount`** | S1 | 15→15 | form body `_method=DELETE` on `POST /api/v1/accounts/acc-alice-1` |
| X4 | `postAccount` → **`updateAccount`** | S1 | 12→12 | form body `_method=PUT` |
| X5 | `getAccount` → **`deleteAccount`** | S1 | 1→1 | single header line `X-HTTP-Method-Override: DELETE` |

All eight are 1-minimal with respect to the canonical request (every remaining unit is required for the
identical executed `(op_id, path_params)`; `still_hit=true` on the minimised request, re-sent live). X1/X2
cannot shrink below the appended suffix bytes, because the predicate demands the identical executed op.
X5 reduces to a single header; X4 to a single 11–14-byte form body; X3 to one dot segment. The fragment
RCs (X1, X2) were minimised on `nginx×fastapi/ovon`, X5 likewise; X4 (form `_method`) on
`nginx×express/ovon` (POST-only override, the default-shape middleware). `\*` X2/X3 carry oracle severity
S1 (deviation kind `resource`) but are practically low (§5.2, §5.3): the suffix/dot segment cannot reach a
different resource. Raw minimised requests and the per-trial `ddmin` ladder: `ddmin/<id>__<case>.json`.

## 9. Candidate disclosures
See `FINDINGS.csv`. Candidates are reported as research observations; **no vendor was contacted.** The
highest-value item is the fragment nested-route substitution on nginx + `#`-keeping servers (F1/F2).

## 10. Files
- `bench-api.v2.openapi.yaml` — v2 OpenAPI; `conformance/run_conformance.py --v2` — v2 conformance.
- `scripts/ext_base.py` (v2 base ops + custom fragment primitives), `ext_run_matrix.py`, `ext_rerun.py`,
  `ext_ddmin.py`, `ext_probe.py`, `analyse.py`.
- `runs/<id>/` raw logs + oracle output; `reruns/<id>/` determinism; `ddmin/` minimisation + probes;
  `analysis/` aggregates; `groundtruth/` per-(fw,override) ground truth; `topologies/` 32 YAMLs.
- Harness change: `harness/executors/laravel/Dockerfile` gained `HEALTHCHECK NONE` (the frankenphp base
  image's inherited `curl localhost:2019/metrics` healthcheck can never pass under our `admin off`
  Caddyfile, so `compose up --wait` failed for every laravel topology; readiness is validated by the
  orchestrator `probe` sidecar). Affects the image build only; no request-handling behaviour changes.
