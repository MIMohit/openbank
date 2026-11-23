# Extension round — W14: remaining frameworks + origin placement

Data: **80 topologies × 948 depth-1 cases = 75,840 raw requests**, all real components (`orchestrator.up --stubs off`),
run 2026-11-23. Matrix:
- **(a) framework breadth:** {nginx, traefik, envoy} × {default, recommended} × placement=edge ×
  {**django, go-chi, rails, laravel**} × override {off, on} = **48 topologies**, A_leak kill methodology.
- **(b) A3 ablation (origin placement):** {nginx, envoy} × profile=default × {origin, both} × **all 8 frameworks** ×
  override on = **32 topologies**, to test whether verifying at the app with the raw target (`VERIFY_MODE=origin-raw`)
  removes or creates hits.

Images: nginx 1.30.7-alpine, traefik v3.7.19, envoy v1.39.6, `bh-verifier:latest` (HTU_CANON=rfc3986, JTI_CACHE=on,
IAT_WINDOW=60), `bh-exec-{django,go-chi,rails,laravel,fastapi,express,spring,aspnet}:latest`.
Every number is traceable to `runs/*/hits.jsonl`, `runs/summary.csv`, `reruns/*/rerun_outcome.jsonl`,
`ddmin/*.json`, `runs_a3host/*` (A3 §A3) and `analysis/*.csv`. Root-cause detail: `notes/ROOT_CAUSES.md`.

Ownership/process: I wrote only inside `binding/experiments/ext-fw/`. No git commits. All compose projects/containers
prefixed `w14-bh-`. One topology up at a time; each torn down. No prune. Docker clock skew checked before every rerun
(`rerun_hc.py:clock_check`, max 5 s); the main runs contain **0** `iat_skew` denials.

## 0. Verdict (gate criteria, CONTRACT §12)

| criterion | result |
|---|---|
| (a) ≥ 2 **independent** topology classes with binding resolution > 1 caused by **G2 or G3** on current releases, default/documented configs | **NOT MET from this worker's data.** Exactly **one** G2 class (the `#`-fragment differential, RC6/RC7), now shown to generalise from fastapi to **go-chi and laravel** (3 server stacks, 3 distinct mechanisms) under **nginx** (resource substitution) and **traefik** (query-only). **Zero** G3 binding hits. |
| (b) G1 reachable in default/common configs of ≥ 2 major frameworks | **MET, and strengthened.** By-design query (RC1) and body (RC2) dispatch change the executed op under one proof in **all 4 new frameworks**, both profiles, both overrides, behind all 3 gateways: 48/48 edge topologies. Additionally, **Laravel ships method-override ON by default with no off switch, and the W5 Rails app is a non-API app that ships `Rack::MethodOverride` in its default stack** — so a *framework-level* method-override lever is **on by default** in 2 of the 4 new frameworks (RC5). It does not become an oracle *hit* only because of the bench route-space gap (see §5, §A3). |

**Independent G2/G3 classes found by W14: 1** (the `#`-fragment class; same class W9 called RC6, extended to more frameworks/gateways). **G3 binding classes: 0.** This does not, on its own, clear the §12 hard-kill bar of 2 independent G2/G3 classes.

## 1. Headline numbers

| | value |
|---|---|
| cases sent / transport errors | 75,840 / **0** |
| verifier-accepted | 55,332 |
| raw hits | **694** (S1 391, S2 303, S3 0) |
| by class | g1 **630**, g2 **64**, g3 **0** |
| &nbsp;&nbsp;(a) edge, 48 topos | 604 hits (g1 540, g2 64; see §2) |
| &nbsp;&nbsp;(b) origin, 16 topos | 90 hits — **all 8 under envoy-origin; nginx-origin 0 (artefact, §A3)** |
| &nbsp;&nbsp;(b) both, 16 topos | **0** — artefact (jti replay, §A3) |
| B0 verifier bypass | **0** |
| confirmed 3/3 on fresh topologies | **694 / 694** (0 flaky, 0 irreproducible; see §3) |
| distinct cross-topology signatures | 30 (23 g1, 7 g2 incl. dispatch/resource splits) |
| root causes | RC1–RC7 (`notes/ROOT_CAUSES.md`), mapping onto W9's RC1–RC7 |
| G3 propagation findings (separate predicate, not counted) | S1 totals nginx 4264, traefik 1976, envoy 3029 — largely oracle artefacts (§4) |
| nonconformant ground truth | 0 (all 8 framework × override ground truths conform) |

## 2. Hits per gateway × profile × framework × override — part (a), edge

Cell = total hits (`g1` / `g2`). Source: `analysis/hits_per_topology.csv`.

| gw / profile | django/off | django/on | go-chi/off | go-chi/on | rails/off | rails/on | laravel/off | laravel/on |
|---|---|---|---|---|---|---|---|---|
| nginx/default | 13 (13/0) | 9 (9/0) | **19 (12/7)** | **17 (10/7)** | 14 (14/0) | 10 (10/0) | **20 (13/7)** | **16 (9/7)** |
| nginx/recommended | 13 (13/0) | 9 (9/0) | **19 (12/7)** | **17 (10/7)** | 14 (14/0) | 10 (10/0) | **20 (13/7)** | **16 (9/7)** |
| traefik/default | 13 (13/0) | 9 (9/0) | 13 (12/1) | 11 (10/1) | 14 (14/0) | 10 (10/0) | 14 (13/1) | 10 (9/1) |
| traefik/recommended | 13 (13/0) | 9 (9/0) | 13 (12/1) | 11 (10/1) | 14 (14/0) | 10 (10/0) | 14 (13/1) | 10 (9/1) |
| envoy/default | 13 (13/0) | 9 (9/0) | 12 (12/0) | 10 (10/0) | 14 (14/0) | 10 (10/0) | 13 (13/0) | 9 (9/0) |
| envoy/recommended | 13 (13/0) | 9 (9/0) | 12 (12/0) | 10 (10/0) | 14 (14/0) | 10 (10/0) | 13 (13/0) | 9 (9/0) |

Observations:
- **Profile has no effect on hits** — default and recommended are byte-identical for every cell. The recommended profiles
  change header hygiene / normalisation that does not touch query, body, override headers, or `#` on nginx.
- **G1 is uniform across gateways** for a given framework × override (the dispatch gap is a property of the proof's view, §RC1/RC2).
- **The gateway matters only for G2 (`#`).** nginx forwards `#` in path+query → resource substitution (g2=7: 6 resource ops +
  1 query-dispatch) on go-chi and laravel. traefik forwards `#` only in the query → g2=1. envoy 400s `#` → g2=0.
- Override **on reduces** G1 hits (the `_method`/content-type body primitives turn POST dispatch into `unknown`/404 rather than a chosen op);
  for the 4 new frameworks it never *adds* a hit, because none of them overrides a *non-POST* method and no non-POST route shares a POST path (§RC5).

## 3. Determinism reruns (oracle_spec §10)

Every hit case of every topology that produced ≥ 1 hit (56 topologies) was re-run **3×**, each on a freshly started
topology (`down → up --stubs off --fresh-logs → send hit cases with fresh proofs → down → correlate`),
via `scripts/rerun_hc.py`. A rep in which the gateway briefly failed ext_authz open before the verifier was ready
(0 verifier records, whole-rep B0 bypass) is an infra-readiness failure, not a determinism result; it is discarded and
re-tried, the same treatment oracle_spec §10 gives `rerun_timing_deny`.

- **All 694 hits confirmed 3/3** across the 56 topologies that had hits — 0 flaky, 0 irreproducible, 0 up-failures (`reruns/*/rerun_outcome.jsonl`).
- Clock: every rerun passed `clock_check` (< 5 s skew); 0 `iat_skew` denials in the kept reps. A handful of cold-start ext_authz-open reps were detected (empty verifier log) and re-tried per the §10 `rerun_timing_deny` treatment, so no bypass rep polluted a count.

## 4. G3 (propagation predicate only)

**0 G3 binding hits** (no executed-op change) in any of the 80 topologies — the bench API does not act on trust headers.
The separate propagation predicate (oracle_spec §8) raises S1 totals of nginx 4264, traefik 1976, envoy 3029. As W9
established and this round reproduces: a large share are **oracle artefacts** — the `X-Verified-Sub: alice` marker equals
the legitimate subject the gateway sets, so the executor merely echoes the gateway's own value — and the remainder is
generic header pass-through (`X-Forwarded-Client-Cert`, `Client-Cert`) that is a backend-trust/W6-config question, not a
vendor binding bug. Not counted toward the gate.

## 5. Method override, measured precisely (task ask)

Per the task, measured which proof `htm` leads to which executed method under **default** configs (join runner→executor by
`jti`, `effective_method` vs proof `htm`; full dump reproduced from `runs/*/executor.jsonl`):

| framework | stock default | mechanism (W5 source) | honoured inputs | real method? | op hit here? |
|---|---|---|---|---|---|
| **laravel** | **override ON, no off switch** | symfony/http-foundation 7.4.23 `Request::getMethod()`, Laravel `enableHttpMethodParameterOverride()` | `X-HTTP-Method-Override` (wins), `_method` in form/query/JSON | yes, POST→X | **No** (route gap) |
| **rails** | **override ON** (non-`api_only` app ⇒ `Rack::MethodOverride` in default stack) | `rack-3.2.9/.../method_override.rb`, `ALLOWED_METHODS=[POST]` | `_method` (form) then `X-HTTP-Method-Override` header | yes, POST→X | **No** (route gap) |
| django, go-chi | override OFF by default | — | — | n/a | No |
| fastapi (ref, part b) | OFF (no stock override); W4 Flask-pattern when on | `HTTPMethodOverrideMiddleware`, **any** method | `X-HTTP-Method-Override` | yes, GET/PUT/DELETE↔ | **Yes** (RC5, §A3) |

Measured decoupling (rails/laravel, override on): `POST /api/v1/accounts/{id}/actions` + `_method=DELETE` →
`effective_method=DELETE`; `+ X-HTTP-Method-Override: PUT` → `effective_method=PUT`. The proof bound `htm=POST`; the
executor ran another verb. **This is a genuine method-binding gap that is ON by default for Laravel and non-API Rails.**
It does not become an oracle hit because the only POST routes (`/actions`, `/transfers`, `/graphql`) share no path with a
non-POST route, so POST→{GET,PUT,DELETE,PATCH} always 404s — the **RC5/§6 route-coverage gap** from the kill experiment.
The gap is architectural; the bench route space cannot turn it into an executed op. (W15's v2 route space, with a POST route
sharing a path, is where this would become a default-config hit.)

## 6. ddmin minimisation (oracle_spec §9)

All hits are depth-1 (one primitive), so primitive-set minimisation is trivial (already 1-minimal, `hits.jsonl:"minimal":true`).
`scripts/ddmin_hit.py` additionally minimises each distinct root cause's request **delta** against a live topology (target
bytes, added header lines, body bytes, method), keeping the identical executed `(op_id, path_params)`. Representative result
per root cause (`ddmin/*.json`):

| root cause | case (topology) | units full→min | minimal request (first line) | note |
|---|---|---|---|---|
| RC1 query dispatch | g1-op-freeze-to-close (nginx-edge-go-chi/off) | 4→4 | `POST /api/v1/accounts/acc-alice-1/actions?op=close` | irreducible: `op=close` |
| RC2 body dispatch | g1-gql-to-deleteProfile (go-chi/off) | 6→6 | `POST /api/v1/graphql` + body `{"operationName":"deleteProfile"}` | irreducible op name |
| RC3 content-type | g1-ct-urlencoded (go-chi/on) | 1→1 | `POST /api/v1/graphql` + `Content-Type: application/x-www-form-urlencoded` | single header line |
| RC4 form `_method` | g1-fmethod-get (go-chi/off) | 12→1 | `POST /api/v1/graphql` + body `_method=…` | 1 unit (body kills `operationName`) |
| RC5 header override | g1-hdr-xhmo-delete (envoy-origin-fastapi/on) | 1→1 | `GET /api/v1/accounts/acc-alice-1` + `X-HTTP-Method-Override: DELETE` | single header line |
| RC6 fragment-resource | g2-fragment getAccount (nginx-edge-go-chi/off **and** laravel/off) | 5→5 | `GET /api/v1/accounts/acc-alice-1#frag` | irreducible `#frag` suffix |
| RC7 fragment-in-query | g2-fragment accountAction (nginx-edge-go-chi/off) | 5→1 | `POST /api/v1/accounts/acc-alice-1/actions?op=freezeg` | **1 byte**: confirms it is query dispatch, not a fragment effect |

All minimal requests reproduce the identical executed `(op_id, path_params)` (`still_hit: true` in every `ddmin/*.json`).

## 7. Candidate disclosures

See `FINDINGS.csv`. No vendor was contacted. The one novel technical candidate is the cross-framework `#`-in-path handling
(go-chi / Go `net/http`, and Laravel / FrankenPHP-Caddy percent-encoding `#` into the path parameter), joining W9's uvicorn/h11
finding. All are low practical severity in this route space (suffix of the last segment only) and are conditional on a gateway
(nginx) that forwards a `#` that RFC 9112 forbids in the request-target.

---

## §A3. Origin-placement ablation (deliverable b)

**Question.** Does moving verification to the app with the raw target (`VERIFY_MODE=origin-raw`, placement=origin), or adding
it to the edge check (placement=both), remove or create binding hits?

### A3.1 Clean result — envoy-origin

envoy preserves the client `:authority` (`api.bench.test`) to the executor, and in pure `origin` the verifier is called exactly
once per request (by the executor), so the measurement is clean:

| framework | origin hits | class | note |
|---|---|---|---|
| fastapi | 19 | g1 | RC1–RC4 dispatch + **6 RC5 `(method,route)`** header-override hits on `/accounts/{id}` |
| express | 11 | g1 | dispatch |
| spring | 11 | g1 | dispatch |
| aspnet | 11 | g1 | dispatch |
| django | 9 | g1 | dispatch |
| go-chi | 10 | g1 | dispatch |
| rails | 10 | g1 | dispatch |
| laravel | 9 | g1 | dispatch |

**Conclusion: origin-raw verification does NOT remove the G1 differentials.** `origin-raw` sends `X-Original-URI` = the raw
target (htu canon still strips query/fragment) and `X-Original-Method` = the *raw* method, so exactly the by-design query/body
dispatch (RC1–RC4) and the any-method header override (RC5, fastapi) survive — the verifier at the app sees the same view the
edge verifier saw. It does not *create* any new hit. It removes the G2 `#`-fragment hits only incidentally: envoy 400s a `#` in
the path at the gateway before the executor ever receives it (not a property of origin verification).

### A3.2 nginx-origin = 0 hits is a HARNESS ARTEFACT (not a defence)

nginx's default profile emits a bare `proxy_pass http://executor:8080;` with **no `proxy_set_header Host`**, so nginx rewrites
the upstream `Host` to `executor:8080`. The executor's `origin-raw` call then forwards `X-Original-Host: executor:8080`, the
verifier reconstructs the view URL as `http://executor:8080/...`, and **every** request — including the sound baseline — is
denied `htu_mismatch` against the proof's `http://api.bench.test/...` (measured: `runs/w14-nginx-default-origin-*/verifier.jsonl`
shows `view_host=executor:8080`, 0 `allow`). This is nginx's documented default Host behaviour, not origin verification working.

Corrected run (`scripts/up_hostfix.py` adds `proxy_set_header Host $host;`, a §12 local work-around; `orchestrator/` and
`gateways/` untouched), in `runs_a3host/`:

| framework | nginx-origin hits (Host-fixed) | composition | vs envoy-origin |
|---|---|---|---|
| fastapi | 26 | 13 dispatch + 6 RC5 method + 7 `#`-fragment | envoy 19 (no fragment: envoy 400s `#`) |
| go-chi | 17 | 10 dispatch + 7 `#`-fragment | envoy 10 |
| laravel | 10 | dispatch + fragment (FrankenPHP `%23`) | envoy 9 |
| aspnet | 11 | dispatch | envoy 11 |
| express | 11 | dispatch | envoy 11 |
| spring | 11 | dispatch | envoy 11 |
| django | 9 | dispatch | envoy 9 |
| rails | 10 | dispatch | envoy 10 |

(`runs_a3host/summary.csv`; `view_host` now `api.bench.test`, 0 blanket `htu_mismatch`.) With the Host preserved, nginx-origin
reproduces the envoy-origin G1 dispatch result on all 8 frameworks, **and additionally keeps the G2 `#`-fragment hits** (fastapi,
go-chi, laravel) because nginx forwards `#` to the executor whose `origin-raw` verifier call strips it (allow) before the handler binds
it. So app-side origin-raw verification removes **neither** the G1 dispatch/override **nor** the G2 fragment differential.
These hits instantiate signatures already confirmed 3/3 on the edge topologies; they were additionally re-run 3× (`reruns_a3host/`): all 105 confirmed 3/3, 0 flaky.

### A3.3 both = 0 hits (nginx AND envoy) is a HARNESS ARTEFACT (not a defence)

`placement=both` calls the single `JTI_CACHE=on` verifier **twice** per request: the edge adapter first, then the executor's
`origin-raw` call. A jti is recorded in the replay cache on the edge *allow* (oracle_spec §10), so the second call is denied
`jti_replay` — for **every** request, the sound baseline included (measured: 606/948 `jti_replay` on envoy-both; 772 on
nginx-both which also carries the Host artefact). DPoP's one-time `jti` makes "verify the same proof at the edge *and* again at
the origin against one stateful verifier" self-defeating: the origin leg always fails closed as a replay. `both` therefore
yields 0 hits trivially and measures the replay cache, not binding. A meaningful `both` measurement would need either
`JTI_CACHE=off` on the origin leg or an origin that trusts the edge decision (D-A/D-B, W11) rather than re-verifying the proof.

### A3.4 A3 takeaway

Verifying at the app with the raw target (`origin-raw`) **does not fix operation under-binding**: the G1 query/body/override
differentials pass through it unchanged (envoy-origin, all 8 frameworks). The apparent "0 hits" under nginx-origin and under
both placements are harness artefacts (nginx Host rewrite; shared one-time-jti replay cache), not security properties. The
defence that actually closes the gap is binding the *routed* view (D-A, `origin-routed`) or a view MAC (D-B), both out of W14 scope.
