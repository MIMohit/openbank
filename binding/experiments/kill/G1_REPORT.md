# Decision gate G1: kill-experiment report (W9)

Data: 48 topologies × 948 depth-1 cases = 45,504 raw requests, all real components (`--stubs off`), run 2026-11-23.
Images: nginx 1.30.7-alpine, traefik v3.7.19, envoy v1.39.6, `bh-verifier:latest` (HTU_CANON=rfc3986), `bh-exec-{fastapi,express,spring,aspnet}:latest`.
Every number below is traceable to `runs/*/hits.jsonl`, `runs/summary.csv`, `reruns/*/rerun_outcome.jsonl` and `analysis/*.csv`.

## 0. Verdict

| criterion | result |
|---|---|
| (a) ≥ 2 **independent topology classes** on current releases with binding resolution > 1 caused by **G2 or G3** | **NOT MET.** Exactly **one** G2 class: NGINX forwards `#` raw, uvicorn/h11 keeps `#` in the path (RC6), in 4 topologies. Its practical impact is low: only a suffix of the last path segment can be changed, and targeted probes found no route or resource substitution in the bench API. **Zero** G3 binding hits. |
| (b) **G1 reachable in default/common configs of ≥ 2 major frameworks** | **MET, but only in the weak sense.** Query dispatch (RC1) and body dispatch (RC2) change the executed operation under one proof in **all 4 frameworks** with override **off** (the framework default), behind all 3 gateways in both profiles: 48/48 topologies, all confirmed 3/3. That dispatch is an *application* pattern built into the bench API, and RFC 9449 §4.2/§4.3 concedes it by design. The framework-level G1 lever (method override) is **off by default in all four**. It produced op changes only in FastAPI with the Flask pattern enabled (RC5). |

**Formally the gate passes via clause (b) alone.** I recommend the coordinator treat it as a **conditional / weak pass**:
the evidence supports a *G1 measurement* paper (under-binding is real, uniform across stacks and invisible to every gateway profile tested). It does **not**
yet support the claim that *interpretation differentials (G2) or propagation (G3) are a widespread binding failure on current releases*.
Before G2/G3 can be dropped or claimed, the gaps in §6 have to be closed. The biggest are the sparse bench route space, the 3 of 6 gateways covered and the 4 of 8 frameworks covered.

## 1. Headline numbers

| | value |
|---|---|
| cases sent / transport errors | 45,504 / 0 |
| verifier-accepted | 31,432 |
| raw hits | **680** (S1 344, S2 336, S3 0) |
| by primitive class | g1: 648, g2: 32 (24 = RC6 resource substitution [G2]; 8 = RC7 `#` inside the query, an effect equivalent to G1) |
| confirmed 3/3 on fresh topologies | **680 / 680** (0 flaky and 0 irreproducible after redoing clock-skewed reps, see §5) |
| cross-topology signatures / root causes | 30 / 7 (RC1–RC7, `ROOT_CAUSES.md`) |
| B0 verifier bypass | 0 |
| G3 binding hits | 0 |
| G3 propagation findings (separate predicate) | 117 per nginx/traefik topology and 78 per envoy topology. 26 of these per topology are oracle artefacts (§5) |
| nonconformant ground truth | 0 (all 8 framework × override ground truths conform) |

## 2. Hits per gateway × profile × framework × override

Cell = hits (G1-class primitives / G2-class primitives). Source: `analysis/hits_per_topology.csv`.

| gw/profile | fastapi/off | fastapi/on | express/off | express/on | spring/off | spring/on | aspnet/off | aspnet/on |
|---|---|---|---|---|---|---|---|---|
| nginx/default | 20 (13/7) | 26 (19/7) | 15 (15/0) | 11 (11/0) | 14 (14/0) | 11 (11/0) | 14 (14/0) | 11 (11/0) |
| nginx/recommended | 20 (13/7) | 26 (19/7) | 15 (15/0) | 11 (11/0) | 14 (14/0) | 11 (11/0) | 14 (14/0) | 11 (11/0) |
| traefik/default | 14 (13/1) | 20 (19/1) | 15 (15/0) | 11 (11/0) | 14 (14/0) | 11 (11/0) | 14 (14/0) | 11 (11/0) |
| traefik/recommended | 14 (13/1) | 20 (19/1) | 15 (15/0) | 11 (11/0) | 14 (14/0) | 11 (11/0) | 14 (14/0) | 11 (11/0) |
| envoy/default | 13 (13/0) | 19 (19/0) | 15 (15/0) | 11 (11/0) | 14 (14/0) | 11 (11/0) | 14 (14/0) | 11 (11/0) |
| envoy/recommended | 13 (13/0) | 19 (19/0) | 15 (15/0) | 11 (11/0) | 14 (14/0) | 11 (11/0) | 14 (14/0) | 11 (11/0) |

Observations:
- **Profile has no effect on hits.** Default and recommended are identical everywhere. The recommended profiles change normalisation (Envoy) and header hygiene,
  and none of that touches query, body or override headers. It also does not touch `#` in NGINX.
- **The gateway matters only for G2 (`#`).** G1 counts are identical across gateways for a given framework × override.
- Override **on** *reduces* hits for express/spring/aspnet: the `_method` form primitives turn POST /graphql into another method, which gives 404, which is not a hit.
  It *adds* 6 hits for FastAPI (RC5, header override on any method).

## 3. Distinct root causes

| RC | class | mechanism (verifier view vs. executor dispatch input) | where | default profile | recommended | severity (oracle) | resolution added |
|---|---|---|---|---|---|---|---|
| RC1 | **G1** (by design) | query `op` not in htu: `op=close`, unknown, removed, case, HPP dup | 48/48 | yes | yes | S1 | `accountAction.freeze` → {freeze, close, unknown}: res 3 |
| RC2 | **G1** (by design) | JSON body `operationName` not covered | 48/48 (dup-key variant: aspnet only) | yes | yes | S1/S2 | `graphql.getProfile` → {getProfile, deleteProfile, unknown}: res 3 |
| RC3 | **G1** (by design) | Content-Type relabel → body not parsed → `unknown` | express (off/on), spring (off/on), aspnet (on) | yes | yes | S2 | (within RC2's set) |
| RC4 | **G1** (by design) | `_method=X` form body replaces the JSON → `unknown` | all frameworks, override off; fastapi also on | yes | yes | S2 | (within RC2's set) |
| RC5 | **G1** (config) | `X-HTTP-Method-Override` honoured for **any** method (Flask pattern) | fastapi + OVERRIDE=on, all gw/profiles (6 topos) | yes | yes | S1 (GET proof → DELETE) | get/update/deleteAccount → res 3 (4 with RC6) |
| RC6 | **G2** | verifier strips `#…` (RFC 3986 fragment); NGINX forwards the raw target; uvicorn/h11 keeps `#` in the path → `{id}="acc-alice-1#frag"` | nginx × fastapi (off/on), 4 topos | yes | yes | S1 (resource), **practically low** | +1 per path-param op (res 2) |
| RC7 | G1 effect (G2 vehicle) | `?op=freeze#frag` → h11 keeps `#frag` in the query value → `unknown` | nginx × fastapi, traefik × fastapi (8 topos) | yes | yes | S1 | none beyond RC1 |

**Independent topology classes (oracle_spec §9 item 3):** RC1–RC4 are one class, *application dispatch outside the binding* (the verifier is the cause).
RC5 is one framework-level class (FastAPI + Flask-pattern override). RC6 is one gateway × framework class. RC7 is subsumed by RC1.
Under G2/G3 there is **one** class (RC6). Under G1 there are 2 classes (dispatch, header override).

Minimised requests: `ddmin/*.json`. All are 1-minimal with respect to the canonical request. RC5 reduces to the single header line `X-HTTP-Method-Override: DELETE`.
RC7 reduces to *any* extra byte in the `op` value (`op=freezeg`), which confirms it is query dispatch and not a fragment effect.
RC1/RC2/RC6 cannot shrink further, because the predicate demands the identical executed `(op_id, path_params)`.

## 4. Resolution distribution (oracle_spec §4, `analysis/resolution.csv`)

`res_hat` per (topology, base op), over 48 × 13 = 624 pairs: **1: 492, 2: 18, 3: 108, 4: 6.**

| base op | res_hat (topologies) | cause |
|---|---|---|
| accountAction.freeze | 3 (48) | RC1 (G1) |
| graphql.getProfile | 3 (48) | RC2–RC4 (G1) |
| getAccount / updateAccount / deleteAccount | 4 (2: nginx × fastapi/on), 3 (4: traefik/envoy × fastapi/on), 2 (2: nginx × fastapi/off), 1 (40) | RC5 (G1) + RC6 (G2) |
| getAccountV2 / adminDeleteUser / publicFile | 2 (4: nginx × fastapi), 1 (44) | **RC6 only (G2)** |
| listAccounts, me, health, adminListUsers, createTransfer | 1 (48) | none |

**Resolution > 1 caused by G2: only the nginx × fastapi pairs (RC6).** Targeted probes (`ddmin/probe_fragment__*.jsonl`) tried to turn RC6 into a
route or owner change: `…/acc-alice-1#/../../admin/users`, `…#/actions`, `…#%2F..%2Facc-bob-1`, `/accounts#/acc-bob-1`,
`/public/logo.png#/../../accounts/acc-bob-1`, `/admin/users#/u-1`, `…#/../acc-bob-1`. All of them were *allowed by the verifier* and all gave **404**.
uvicorn does no dot-segment removal, and Starlette's literal segments do not match `accounts#`. So in this route space, RC6 can only produce suffixed ids.

## 5. Skepticism: what might be a harness artefact

1. **By-design G1 dominates (648/680 hits).** The bench API *was built* with query and body dispatch (CONTRACT §3). Those hits measure the RFC's stated
   scope, not a deployment bug. Clause (b) is satisfied by construction. Prevalence of such dispatch in real APIs comes from W8, not from here.
2. **RC5 depends on W4's override choice.** FastAPI has no stock override, so W4 transliterated Flask's documented pattern. A real FastAPI app with
   override is rare, and it is off by default. Do not present RC5 as a FastAPI default.
3. **RC6 severity is inflated by the oracle rule.** "Same op, different `path_params`" is S1 per oracle_spec §4/§5, but the id differs only by a `#…` suffix.
   The handler did run: the response body's `op_id` matches the executor log, status 200, and the id was echoed. But no other existing resource is reachable.
4. **G3 propagation artefacts.** `g3-xverified-sub-alice` and `g3-xverified-sub-dup` use the marker `alice`, which *equals the legitimate subject*. The executor only shows the
   gateway-set value, because all three gateways overwrite `X-Verified-Sub/Jkt`. That gives 26 findings per topology (2 primitives × 13 ops), and they are false positives of the §8 predicate. A fix (marker distinct from the legitimate value) should go to W7/W2.
5. **Clock skew.** Host sleep made the Docker VM clock lag the host by ~23 min. During the first rerun pass this caused verifier `iat_skew` denials, which the outcome file showed as "flaky".
   Those reps were moved to `*.iat_skew_discarded` and redone after a clock check (`rerun.py --redo-skewed`, oracle_spec §10 `rerun_timing_deny`).
   The 48 main runs contain no `iat_skew` deny.
6. **Uncorrelated executor records**: 449 in total, ~9 per topology. These are the orchestrator probe's direct `/api/v1/health` calls (`jti=null`) and are not hits.
7. **`allowed_not_executed`** (13 per topology on nginx × spring/aspnet; 1 per traefik × spring/aspnet: the `?…#frag` case): Tomcat or Kestrel reject `#` with 400 after the verifier allowed it. This is sound behaviour.
8. **Single client, edge only, depth-1.** Owner substitution across clients (alice proof → bob resource) is only exercised through path primitives, all of which were denied or gave 404.
9. **Latent G2, L1 (dot segments)**: in nginx default/recommended and envoy default, 468 cases are *allowed* by the RFC 3986 verifier but 404 at every executor, because the
   routers do not remove dot segments. This is a genuine verifier/router disagreement that the bench route space cannot turn into an op change. It is **not** counted.

## 6. What would change the verdict (recommended follow-ups before the paper commits)

1. **Route space.** Add a POST route that shares a path with PUT/DELETE (e.g. `POST /api/v1/accounts/{id}` or `POST /api/v1/accounts` + `GET`), which exercises the
   **POST-only override in express, spring and aspnet**. Add a nested same-method route (`GET /accounts/{id}/statements`), which turns RC6 into a route change.
   Add a catch-all (`/files/{path:path}`), which turns L1 into an op change.
2. **The other 3 gateways** (kong, apisix, haproxy) and **4 frameworks** (django, go-chi, rails, laravel) are in the harness but not in this matrix.
   Rails (`Rack::MethodOverride` is in the default middleware stack of non-API Rails apps) and Laravel (form `_method` spoofing; to be verified against W5's executors) are the most likely to give a
   **default-config** framework-level G1 (override) result. That would make clause (b) strong rather than trivial.
3. **Origin placement / verifier at the app (VERIFY_MODE=origin-raw)**, where the verifier sees the raw target with no gateway normalisation.
4. **uvicorn with httptools** (the `uvicorn[standard]` install) as a contrast for RC6.

## 7. Candidate disclosures
See `FINDINGS.csv`. One low-severity candidate: **F1**, uvicorn's h11 implementation accepting `#` in the request-target and keeping it in `path`.
Check the upstream tracker for prior reports before disclosing. F2–F5 are informational, configuration or by-design items. No vendor was contacted.
