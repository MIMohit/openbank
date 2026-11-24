# Binding-soundness project: shared contract

This file is the single source of truth that lets parallel workers build compatible components.
Only the coordinator edits it. If you need a change, raise it with the coordinator (`orca orchestration ask`) instead of working around it.

Plan reference: research/ASIACCS2027_research_directions.md, plus the published plan at https://claude.ai/artifact/6rdXSAjgm5gNtGcJiBk8eW.
Paper thesis: **binding soundness.** If a verifier accepts a DPoP proof π for its view v(r) = (method, URI), the backend must execute exactly one operation, op(π). The three failure classes are:
- **G1, under-binding by design:** the query, headers, body and method override are not covered by the proof.
- **G2, interpretation differentials:** the verifier and the router parse the method or URI differently.
- **G3, binding propagation:** spoofable trust headers.

Open Banking is NOT the framing.

## 0. Rules for every worker
- Root: `/Users/mimohit/openbank/binding/`. Write ONLY inside the directories you own (§9). You may read anything.
- Do NOT `git commit`, `git push`, switch branches or rewrite history. The coordinator commits.
- Docker:
  - Prefix every compose project and container name with your worker tag, e.g. `docker compose -p w4-fastapi`.
  - Tear down what you start.
  - Never run `docker system prune`, `docker volume prune`, or anything that removes resources you did not create.
  - The machine is a 16 GB / 10-core Mac shared by 8 workers. Keep your running containers under about 3 GB in total and build images one at a time.
- Tooling language: Python 3.12 unless your component is a framework app. Each component keeps its own `requirements.txt`.
- Never fabricate results. Record what ran, its exact versions, and its raw output. If something can't be done, say so in your README.
- Every component directory gets a `README.md` covering: what it is, how to run it, how to test it, and its known limitations.

## 1. Network identity used in all experiments
- Public origin: `http://api.bench.test`. Requests carry `Host: api.bench.test`. TLS is out of scope for the harness because path and method logic is independent of TLS; the paper states this.
- DPoP `htu` for an operation is `http://api.bench.test` + the canonical path from §3, with no query string. `htm` is the canonical method.
- Inside a topology, the docker network has these service names: `gateway` (listens on 8000), `verifier` (9100), `executor` (8080).

## 2. Tokens and keys (test authorization server, no Keycloak dependency)
- The minter owns a test AS key pair, an ES256 P-256 JWK: `harness/keys/as_priv.jwk` and `harness/keys/as_pub.jwk`. It is generated once by `python -m minter.keys`. Commit only the public key.
- Access token: a JWS with ES256 and `typ: at+jwt`. Claims:
  - `iss=https://as.bench.test`, `aud=https://api.bench.test`, `sub`, `scope`, `iat`, `exp` (+3600 s), `jti`
  - `cnf.jkt`: the RFC 7638 thumbprint of the client DPoP key
- Clients: `alice` (owns `acc-alice-1`) and `bob` (owns `acc-bob-1`). Each has its own ES256 DPoP key, stored as `harness/keys/client_<name>.jwk`.
- DPoP proof (RFC 9449):
  - Header: `typ=dpop+jwt`, `alg=ES256`, `jwk` (public key).
  - Claims: `jti` (UUID4, fresh for every request), `htm`, `htu`, `iat`, `ath` (base64url SHA-256 of the access token).
- Requests carry `Authorization: DPoP <at>` and `DPoP: <proof>`.
- **Correlation id:** the proof's `jti`. Every component logs it. Executors read it by base64url-decoding the DPoP header payload WITHOUT verifying it. Missing or unparseable header: `jti=null`.

## 3. Bench API: identical in every framework (executors)
`op_id` is what gets logged. All paths are under `/api`. Responses are JSON `{"op_id": ..., "framework": ..., "method": <effective>, "path_params": {...}}` with status 200. Any unmatched request gets 404 with `op_id: "NOT_FOUND"`, and is logged.

| op_id | method | path template | notes |
|---|---|---|---|
| listAccounts | GET | /api/v1/accounts | |
| getAccount | GET | /api/v1/accounts/{id} | |
| updateAccount | PUT | /api/v1/accounts/{id} | |
| deleteAccount | DELETE | /api/v1/accounts/{id} | |
| accountAction.freeze / accountAction.close / accountAction.unknown | POST | /api/v1/accounts/{id}/actions | dispatched by the query param `op` (G1 query dispatch) |
| createTransfer | POST | /api/v1/transfers | |
| graphql.getProfile / graphql.deleteProfile / graphql.unknown | POST | /api/v1/graphql | dispatched by the JSON body field `operationName` (G1) |
| me | GET | /api/v1/me | |
| adminListUsers | GET | /api/v1/admin/users | |
| adminDeleteUser | DELETE | /api/v1/admin/users/{id} | |
| health | GET | /api/v1/health | |
| publicFile | GET | /api/v1/public/{file} | |
| getAccountV2 | GET | /api/v2/accounts/{id} | mounted as a sub-app/router under `/api/v2` (prefix mount) |

The canonical OpenAPI file is `harness/executors/bench-api.openapi.yaml`, owned by W4.

Executor environment variables:
- `OVERRIDE=off|on` (default `off`). When `on`, enable that framework's standard, documented method-override mechanism, honouring both `X-HTTP-Method-Override` and `_method` where the framework supports them. Use the framework's own or its de-facto standard middleware and NOT custom code. Record which one in the README.
- `VERIFY_MODE=off|origin-raw|origin-routed` (default `off`):
  - `origin-raw`: before the handler runs, call `http://verifier:9100/authz/orig` with `X-Original-Method` = the raw request method, `X-Original-URI` = the raw request target exactly as received, `X-Original-Host` = Host. Forward `Authorization` and `DPoP` unchanged.
  - `origin-routed` (defence D-A): the same call, but `X-Original-Method` = the effective method after override resolution, and `X-Original-URI` = the canonical path from §3 that the router actually matched, with path params substituted, and no query.
  - Deny (non-2xx): respond 401 and log `op_id` with `"denied": true`.
- `FRAMEWORK_TAG` (e.g. `fastapi`).

Executor log: one JSON line per request to stdout AND appended to `/logs/executor.jsonl` (bind-mounted). Fields:
```
{"ts": iso8601, "framework": str, "jti": str|null, "op_id": str, "route_template": str|null,
 "raw_method": str, "effective_method": str, "raw_target": str, "path_params": {}, "query": str,
 "trust_headers": {lower-case name: value for any header starting with x-forwarded-, x-original-, x-verified-, x-client-cert, client-cert, x-forwarded-client-cert, x-auth-},
 "denied": bool, "status": int}
```

## 4. Reference verifier (W3), HTTP service on :9100
Adapters: each reads the client's original request view, then runs the same RFC 9449 §4.3 checks.
- `ANY /authz/fwd`: view from `X-Forwarded-Method`, `X-Forwarded-Proto`, `X-Forwarded-Host`, `X-Forwarded-Uri`. Used by Traefik ForwardAuth, APISIX forward-auth and Caddy.
- `ANY /authz/orig`: view from `X-Original-Method`, `X-Original-URI`, `X-Original-Host`, `X-Original-Proto` (default http). Used by NGINX auth_request, HAProxy, Kong and the executors in origin mode.
- `ANY /authz/envoy/{rest}`: Envoy ext_authz HTTP service with `path_prefix=/authz/envoy`. The method is the request method; the path and query come from the remainder.
- `GET /health`.

Decision:
- **Allow:** 200, with response headers `X-Verified-Sub`, `X-Verified-Jkt`, and, if `VIEW_MAC=on`, also `X-Verified-View` (see §8).
- **Deny:** 401, with `WWW-Authenticate: DPoP error="invalid_dpop_proof"` or `invalid_token`.

Environment variables:
- `HTU_CANON=rfc3986|none|strict` (default `rfc3986`, the RFC 9449 §4.3 syntax- and scheme-based normalisation; query and fragment ignored)
- `JTI_CACHE=on|off` (default `on`)
- `IAT_WINDOW=60`
- `VIEW_MAC=off|on`
- `VIEW_MAC_KEY`

Verifier log, `/logs/verifier.jsonl`:
```
{"ts", "adapter", "jti", "view_method", "view_uri", "view_host", "htm", "htu", "canon_mode",
 "decision": "allow"|"deny", "reason": str, "sub", "jkt"}
```
The verifier also ships as an importable Python library (`verifier.core.verify(view, headers, config) -> Decision`) for unit tests and the mutator.

## 5. Gateways and topologies (W6)
- Gateways: envoy, traefik, nginx, kong, apisix, haproxy. Each routes `/api/` to `executor:8080`, keeping the path. Each has profiles `default`, `recommended` and `strict` (documented in the README with links to vendor docs).
- In `placement=edge` the gateway calls the verifier through the matching adapter (§4). In `placement=origin` the gateway does not call the verifier, and the executor runs with `VERIFY_MODE=origin-raw`. `placement=both` combines the two.
- The gateway must pass `Authorization` and `DPoP` through to both the verifier and the executor.
- **Topology YAML** (`harness/orchestrator/topologies/*.yaml`):
```
id: envoy-default-edge-fastapi-ovoff
gateway: envoy
gateway_image: envoyproxy/envoy:<pinned tag or digest>
profile: default
placement: edge
framework: fastapi
executor_image: bh-exec-fastapi:latest
override: off
verifier: {canon: rfc3986, view_mac: off}
host_port: 18000
```
- `python -m orchestrator.up <topology.yaml>` writes `harness/orchestrator/generated/<id>/docker-compose.yml`, starts it under project name `bh-<id>`, waits for health, and prints the host port. `.down` tears it down.
- Logs: bind-mount `harness/logs/<id>/` into `/logs` for the verifier and the executor.

## 6. Mutator, runner, oracle (W7)
- **Primitive catalogue:** `harness/mutator/primitives/{g1,g2,g3}.yaml`. Each entry has `id`, `class`, `description`, `source` (paper, advisory or RFC citation) and `transform` (operates on a raw request model: method, target, headers list, body).
- **Case:** `{case_id, base_op_id, base_method, base_path, primitive_ids[], client, raw_request_b64}`.
- **Runner flow for each case:**
  1. Mint a fresh token and proof bound to the BASE op's canonical (htm, htu). In the A_leak model a valid proof exists for the base op.
  2. Apply the primitives to the canonical raw request.
  3. Send the exact bytes over a raw TCP socket to `127.0.0.1:<host_port>`. Requests must NOT be normalised by any HTTP library.
  4. Record the status and body in `harness/logs/<topology>/runner.jsonl`.
- **Ground truth:** `op(π)` = the `op_id` the executor returns when the canonical request is sent directly to the executor with no gateway and `VERIFY_MODE=off`.
- **Oracle hit:** verifier decision `allow` (or, in origin placement, executor not denied) AND executor `op_id ∉ {base_op_id, NOT_FOUND}` AND executor status < 400 for that `jti`. Severity:
  - **S1:** state-changing op (PUT, DELETE, POST action, graphql.deleteProfile, admin*), or a different `{id}` / owner.
  - **S2:** a different read.
  - **S3:** health or publicFile.
- **Output:** `harness/logs/<topology>/hits.jsonl` and a summary CSV.

## 7. Prevalence measurement (W8)
Separate from the harness: `binding/prevalence/`. E1 analyses the API corpus (APIs.guru openapi-directory plus named domain specs). E2 surveys framework method-override and dispatch features. Methods and denominators go in its README.

## 8. Defence D-B (view-binding MAC), specified now so W3 can emit it
`X-Verified-View: v1;<base64url(HMAC-SHA256(VIEW_MAC_KEY, jti || "\n" || upper(view_method) || "\n" || canon(view_uri without query) || "\n" || jkt))>`

The executor-side check is built later (wave 2).

## 9. Directory ownership
| Worker | Owns |
|---|---|
| W1 literature | `binding/lit/`, `binding/paper/sections/related.tex` |
| W2 threat model + paper | `binding/paper/` (except `sections/related.tex`), `binding/harness/oracle/oracle_spec.md` |
| W3 minter + verifier | `binding/harness/minter/`, `binding/harness/verifier/`, `binding/harness/keys/` |
| W4 executors A | `binding/harness/executors/{fastapi,express,django,go-chi}/`, `binding/harness/executors/bench-api.openapi.yaml`, `binding/harness/executors/conformance/` |
| W5 executors B | `binding/harness/executors/{spring,aspnet,rails,laravel}/` |
| W6 gateways + orchestrator | `binding/harness/gateways/`, `binding/harness/orchestrator/` |
| W7 mutator + runner + oracle | `binding/harness/mutator/`, `binding/harness/runner/`, `binding/harness/oracle/` (except `oracle_spec.md`), `binding/harness/rawhttp/` |
| W8 prevalence | `binding/prevalence/` |

## 10. Ratified interpretations (coordinator)
- (W3) The VIEW_MAC `canon(view_uri)` is the RFC 3986-normalised PATH only. When a view header appears more than once, `VIEW_DUP=first` is the default; it can be set to `last` or `reject`, and is logged as `view_dup`. The query and fragment are stripped in every HTU_CANON mode. A jti is recorded in the replay cache only when the request is allowed.
- Envoy ext_authz must list `authorization` and `dpop` in `allowed_headers`.

## 11. Wave 2 ownership (coordinator)
| Worker | Owns |
|---|---|
| W9 kill experiment | `binding/experiments/kill/` (read and use every harness component; do NOT edit `orchestrator/`; record any needed fix as a patch file in your directory and work around it locally) |
| W10 paper writing | `binding/paper/` (everything, including `sections/related.tex` for small fixes) |
| W11 defence D-B | `binding/harness/defence/` |
W6 (orchestrator) may resume later and still owns `harness/orchestrator/` and `harness/gateways/`.

## 12. Extension round after gate G1 (coordinator)
Context: binding/experiments/kill/G1_REPORT.md gave a weak pass. 680 hits, all by-design G1. One minor G2 class (RC6). Zero G3 binding hits.
**Hard kill rule for this round:** if, after all four extension workers finish, there are still fewer than 2 independent G2/G3 classes (binding resolution > 1, or an authorization-soundness violation caused by G2/G3) on current releases under default or documented configurations, the paper is reframed as a measurement paper ("the path binding holds, the operation binding doesn't"). Report honestly either way.
Reuse W9's scripts in binding/experiments/kill/scripts (copy them into your directory and adapt; do not edit kill/).
Topologies can override `executor_image` and `verifier: {image: ...}` (see orchestrator/topology.py).
Each worker runs at most ONE topology at a time. The machine is a 16 GB Mac and three runners share it.

| Worker | Owns |
|---|---|
| W12 E4 malicious client + PDP | `binding/harness/pdp/`, `binding/experiments/e4/` |
| W13 remaining gateways | `binding/experiments/ext-gw/` |
| W14 remaining frameworks + origin placement | `binding/experiments/ext-fw/` |
| W15 richer route space (v2 images) | `binding/harness/executors/*/` (source changes MUST be behind env `ROUTES=v2`, default off; build the new images as tag `:v2`; never overwrite `:latest`), `binding/experiments/ext-routes/` |

## 13. Disclosure triage (coordinator)
| Worker | Owns |
|---|---|
| W16 prior-art and advisory check | `binding/disclosure/` |

## 14. Wave 3: evaluation and writing (coordinator). Gate G1 PASSED; see binding/experiments/GATE_DECISION.md
| Worker | Owns |
|---|---|
| W17 defence evaluation (E7, E8, A2) | `binding/experiments/defence/`. May apply `binding/harness/defence/patches/` to the 4 executors ONLY by building separate images tagged `:defence` from a patched copy under its own directory. Never modify the executor source dirs or overwrite `:latest` / `:v2`. |
| W18 binding-claim ablation (A1) + A4/A5 analysis | `binding/experiments/ablation/`. May add verifier binding-claim flags ONLY in a copy under its own directory, built as `bh-verifier:ablate`. Never touch `binding/harness/verifier/`. |
| W19 paper results integration | `binding/paper/` (everything) |

## 15. Wave 4: finish everything except paper writing (coordinator)
| Worker | Owns |
|---|---|
| W20 literature pass 2 | `binding/lit/pass2/` (must not edit `binding/paper/`) |
| W21 APISIX mechanism + G3 gaps | `binding/experiments/g3-apisix/` |
| W22 real-application study | `binding/experiments/realapps/` |
| W23 rerun gaps, cross-gateway FRR, defence path-map fix | `binding/experiments/gaps/`; `binding/harness/defence/` (changes behind env flags only; new images tagged `:pathmap`, never overwrite existing tags) |
| W24 server performance re-run (remote host, strict safety rules in its spec) | `binding/experiments/perf-server/` |
Paper writing is out of scope for this wave: no worker edits `binding/paper/`.

## 13. Final paper wave (coordinator)
Honest reframe per binding/lit/pass2/NOVELTY_UPDATE.md governs ALL claims. The paper is a MEASUREMENT + DEFENCE paper, NOT a "new attacks" paper, and NOT a SoK (no "SoK:" title prefix). Defensible novelty = (i) binding-soundness property+oracle for PoP proofs; (ii) measurement that known G1/G2 mechanisms become operation substitution under a valid leaked proof on current releases; (iii) A1 claim ablation (answers the 2026 IETF htm/htu proposal); (iv) D-B view-MAC defence. Retract APISIX-as-new (deliberate CVE-2026-124680 post-fix behaviour, PR #14035). Recast E4 as reproduction of known patterns (xvnpw 2021, UABScan CCS'25), cite NginxBuster CCS'26 as concurrent.
Agreed figure files in binding/paper/figs/ (W26 produces the matplotlib PDFs; W25 \includegraphics them; W25 owns the 2 TikZ schematics in-tex):
- fig_hits_heatmap.pdf (gateway x framework, G1 and G2 panels)
- fig_resolution.pdf (binding-resolution distribution res_hat 1..4)
- fig_class.pdf (hits by class/primitive family across campaigns)
- fig_ablation_a1.pdf (A1: residual reachable ops vs binding claims: full, -htm, -htu, -ath, +query, +digest)
- fig_defence.pdf (E7 residual hits per defence B-edge/B-origin/B-strict/D-A/D-B/D-C + FRR with 95% CI)
- fig_latency.pdf (p50/p95/p99 at 100 req/s per config, or latency CDF; mark >=500 req/s as saturation, exclude)
| Worker | Owns |
|---|---|
| W25 lead writer | binding/paper/*.tex, main.tex, numbers.tex, extra.bib, appendix/*, README |
| W26 figures | binding/paper/figs/ ONLY (matplotlib PDFs + FIGURES.md); must NOT edit any .tex |
