# Extension round, remaining gateways (W13): kong / apisix / haproxy

Data: **96 topologies** (3 gateways × {default, recommended} × placement edge × 8 frameworks ×
override {off, on}) × 948 depth-1 cases = **91,008** raw requests, all real components
(`orchestrator.up --stubs off`), run 2026-11-23, A_leak model, binding oracle.
Images (pinned in each topology YAML's `gateway_image`): `kong:3.9.5`,
`apache/apisix:3.21.0-debian`, `haproxy:3.2.27`; `bh-verifier:latest` (HTU_CANON=rfc3986),
`bh-exec-{fastapi,express,django,go-chi,spring,aspnet,rails,laravel}:latest`.
Every number is traceable to `runs/*/hits.jsonl`, `analysis/*.csv`, `reruns/*/rerun_outcome.jsonl`,
`ddmin/*.json`, `notes/root_causes.md`. Methodology reuses W9's `kill/` scripts (copied into
`scripts/`, unchanged logic); `harness/orchestrator/` and `harness/gateways/` were not edited.

> **Note on the aggregate.** The analysis first generated at 12:59 predated the final laravel
> runs and silently omitted all laravel topologies. The numbers below are from a **fresh**
> `scripts/analyse.py` over all 96 completed runs (digest: `96 runs present, 0 missing`).

## 0. Verdict (gate §12, for the three gateways W13 owns)

| criterion | result |
|---|---|
| ≥ 1 **new independent** class with binding resolution > 1 caused by **G2/G3**, current releases, default/recommended | **MET — 1 new G2 class (RC-W13-A).** APISIX `forward-auth` sends the **percent-decoded, normalised** path to the verifier (`X-Forwarded-Uri` = nginx `$uri`) while the proxy forwards the **raw** `%2f`-encoded target upstream. The verifier allows the proof-bound view; the executor acts on a different resource id. 96 hits, S1, apisix, **both** profiles, override off+on, 4 frameworks (aspnet, express, go-chi, rails). Confirmed 3/3. Absent on all 6 gateways in `kill/` — genuinely new. |
| distinct G2/G3 classes observed overall | **3** — RC-W13-A (new, above); RC-W13-B fragment-in-path split (genuine G2 = `kill` RC6, on **Kong** incl. laravel; the APISIX fragment hits are RC7/G1 per ddmin §7); RC-W13-C/D trust-header propagation (= `kill`'s G3-propagation class, on all three gateways). |
| by-design G1 separated from G2/G3 | Yes. G1 (query/body dispatch + method override) is uniform across all three gateways and both profiles, identical in mechanism to `kill` RC1/RC2/RC5; it is the RFC 9449 §4.2/§4.3 concession, not a gateway interpretation differential. |

**Count reported to coordinator: 3 distinct G2/G3 classes; 1 of them new and independent
(RC-W13-A, a G2 binding-resolution hit).**

## 1. Headline numbers

| | value |
|---|---|
| cases sent / transport errors | 91,008 / **2** (both non-hit cases; see §6) |
| verifier-accepted cases / not accepted | 65,187 / 25,821 (`summary.csv` `accepted`; "not accepted" = verifier `deny` + gateway-reject + not-executed). Every verifier `deny` observed is `htu_mismatch`; **0** `iat_skew`/`expired` — no clock artefact |
| raw hits | **1368** (S1 768, S2 600, S3 0) |
| by class | g1 **1188**, g2 **180** (oracle label), g3 **0** binding hits |
| genuine G2 after ddmin | **168** (apisix `%2f` 96 + kong fragment 72); the other 12 oracle-g2 are apisix fragment-in-query = RC7/G1 (§7) |
| g2 by gateway | apisix 108 (pct2f 96 + fragment-query 12), kong 72 (fragment-path), **haproxy 0** |
| confirmed 3/3 on fresh topologies | **684 / 684** hit cases across all 48 default-profile topologies (default==recommended, byte-identical, covers every distinct hit); 0 flaky, 0 irreproducible |
| cross-topology signatures / distinct root causes | 42 / see §3 |
| B0 verifier bypass | 0 |
| G3 **binding** hits | 0 |
| G3 **propagation** findings (separate §8 predicate) | client-cert/XFCC on all 3 gateways, X-Verified-View on kong+haproxy; X-Verified-Sub spoof blocked (see §5) |
| nonconformant ground truth | 0 (all 8 frameworks × override conform, incl. laravel) |

## 2. Hits per gateway × framework × override

Cell = hits (g1 / g2). **default == recommended for all 48 (gw,fw,ov) triples** (0 mismatches),
so one row per gateway. Source: `analysis/hits_per_topology.csv`.

**override off**

| gw | fastapi | express | django | go-chi | spring | aspnet | rails | laravel |
|---|---|---|---|---|---|---|---|---|
| kong | 19 (13/6) | 15 (15/0) | 13 (13/0) | 18 (12/6) | 14 (14/0) | 14 (14/0) | 14 (14/0) | 19 (13/6) |
| apisix | 14 (13/1) | 21 (15/6) | 13 (13/0) | 19 (12/7) | 14 (14/0) | 20 (14/6) | 20 (14/6) | 14 (13/1) |
| haproxy | 13 (13/0) | 15 (15/0) | 13 (13/0) | 12 (12/0) | 14 (14/0) | 14 (14/0) | 14 (14/0) | 13 (13/0) |

**override on**

| gw | fastapi | express | django | go-chi | spring | aspnet | rails | laravel |
|---|---|---|---|---|---|---|---|---|
| kong | 25 (19/6) | 11 (11/0) | 9 (9/0) | 16 (10/6) | 11 (11/0) | 11 (11/0) | 10 (10/0) | 15 (9/6) |
| apisix | 20 (19/1) | 17 (11/6) | 9 (9/0) | 17 (10/7) | 11 (11/0) | 17 (11/6) | 16 (10/6) | 10 (9/1) |
| haproxy | 19 (19/0) | 11 (11/0) | 9 (9/0) | 10 (10/0) | 11 (11/0) | 11 (11/0) | 10 (10/0) | 9 (9/0) |

Observations:
- **Profile never changes a hit.** The only config delta is Kong `preserve_host` (false→true,
  not in the binding view), APISIX default-edge == recommended-edge byte-for-byte, and HAProxy
  recommended adds `normalize-uri …` + `http-restrict-req-hdr-names delete` — none of which
  touches the vectors that hit (see §3).
- **G2 is gateway-specific:** only kong (fragment) and apisix (fragment + `%2f`). **haproxy = 0 G2.**
- **G1 is gateway-invariant:** identical g1 counts across all three gateways for a given
  framework × override, matching `kill` across nginx/traefik/envoy.
- Override **on** adds the FastAPI Flask-pattern header override (`g1-hdr-xhmo-*`, S1) and removes
  some `_method`/graphql POST→other-method cases (→404). Same pattern as `kill` RC5.

## 3. Distinct root causes (verifier view vs. executor dispatch input)

| RC | class | mechanism | where | profiles | sev | notes |
|---|---|---|---|---|---|---|
| G1-dispatch | **G1** (by design) | query `?op=` / JSON `operationName` / content-type relabel not covered by htu | all 3 gw, all 8 fw, off+on | both | S1/S2 | = `kill` RC1–RC4; application dispatch, RFC 9449 §4.2/§4.3 |
| G1-override | **G1** (config) | `X-HTTP-Method-Override` honoured on any method (FastAPI Flask pattern); `_method` body | override=on (fastapi header; `_method` several fw) | both | S1 | = `kill` RC5; off by default |
| **RC-W13-A** | **G2** [NEW] | APISIX `forward-auth` → verifier sees **decoded** `$uri`; proxy forwards **raw** `%2f` upstream → executor routes a different `{id}` | **apisix**, fw aspnet/express/go-chi/rails | both | **S1** | 96 hits. express/rails decode `%2f`→`/id`; aspnet/go-chi keep `%2fid` literal. fastapi/django/spring/laravel → 404 (router rejects/decodes). Kong immune: sends raw `request_uri` to verifier → `htu_mismatch` deny. |
| **RC-W13-B** | **G2** | **Kong** forwards `#frag`; executor HTTP parser keeps it in the **path** → `{id}`=`…#frag` (resource) | kong (fastapi/go-chi/laravel, resource) | both | S1 | = `kill` RC6 reproduced on Kong + laravel. 72 hits. Not a new class. |
| RC7 (apisix fragment) | **G1 effect** | APISIX fragment view drops `#`; executor keeps `#frag` in the **query** → `op=freeze#frag` → dispatch to `unknown` | apisix (fastapi/go-chi/laravel, dispatch) | both | S1 | ddmin → 1 byte in the `op` value (§7); = `kill` RC7, a query-dispatch effect, **not** a path split. Oracle labels it g2 (12 hits); corrected here. |
| **RC-W13-C** | **G3** (propagation) | spoofed `Client-Cert`/`X-Client-Cert`/`X-Forwarded-Client-Cert` not stripped at the boundary → reach executor unmodified | all 3 gw | both | S1\* | = `kill` G3-propagation class. Authz violation only if backend trusts mTLS-identity headers (Istio CVE-2021-31920, RFC 9440). Not a binding hit here. |
| **RC-W13-D** | **G3** (propagation) | forged `X-Verified-View` (defence D-B MAC) not stripped → reaches executor | **kong, haproxy** (not apisix) | both | S1\* | Defeats D-B if the executor trusts the header without re-verifying the MAC. Same root cause as RC-W13-C. |

\* severity of a *propagation* finding; it is **not** counted among the 1368 binding hits.

### Why the gateways differ (config evidence, `harness/gateways/*/rendered/{default,recommended}-edge`)
- **Kong** `pre-function` Lua → `/authz/orig` with `X-Original-URI = ngx.var.request_uri` (RAW).
  Verifier therefore sees `%2f` and denies it (`htu_mismatch`) → **no `%2f` hit**; but it sees the
  raw `#frag`, strips it (rfc3986) and allows → **fragment hit**. `strip_path:false`.
- **APISIX** `forward-auth` → `/authz/fwd`; `X-Forwarded-Uri` = decoded/normalised `$uri` while the
  upstream keeps the raw target → **the `%2f` view/execution split (RC-W13-A)** and a fragment
  variant where the verifier view loses the `#`. default-edge == recommended-edge.
- **HAProxy** `bh_authz.lua` sends `X-Original-URI = txn.f:url()` and proxies the **same** parsed
  URI upstream — **one representation, no split → 0 G2**. default has no `normalize-uri`;
  recommended adds `fragment-strip|path-strip-dotdot|path-merge-slashes|percent-decode-unreserved|
  percent-to-uppercase` — defence-in-depth that changes no hit because the default already has no
  split to exploit.

## 4. Resolution (oracle_spec §4, `analysis/resolution.csv`)

`res_hat` over 96 × 13 = 1248 (topology, base-op) pairs: **1: 876, 2: 162, 3: 204, 4: 6.**

| base op | res_hat (where > 1) | cause of the extra resolution |
|---|---|---|
| accountAction.freeze | 3 (all 96) | G1 query dispatch (all 3 gw) |
| graphql.getProfile | 3 (all 96) | G1 body dispatch (all 3 gw) |
| getAccount / updateAccount / deleteAccount | 2–4 | kong(12) fragment-G2, apisix(18) `%2f`-G2, haproxy(2) fastapi-override-G1; res 4 = fastapi/ovon stacks G1-override + G2 |
| **adminDeleteUser / getAccountV2 / publicFile** | **2 (kong 12, apisix 16; never haproxy)** | **purely G2** (kong fragment / apisix `%2f`) — these ops have no query/body/override lever, so the extra resolution is *only* the interpretation differential |
| listAccounts, me, health, adminListUsers, createTransfer | 1 (all) | none |

The `adminDeleteUser / getAccountV2 / publicFile` row is the clean demonstration that G2 adds
binding resolution independent of the by-design G1: resolution rises above 1 **only** behind kong
and apisix, **only** via RC-W13-A/B, and **never** behind haproxy.

## 5. Skepticism: harness artefacts ruled out

1. **Stale analysis (caught & fixed).** The 12:59 aggregate dropped laravel (its runs finished at
   13:13). All numbers here are from a re-run `analyse.py` over all 96 runs. Per-run `hits.jsonl`
   were never wrong — only the first aggregate was.
2. **Clock skew (W9's issue).** Docker VM clock skew = **0 s** at rerun time; **zero** `iat_skew`
   or `expired` denials across the verifier logs (every verifier `deny` observed is `htu_mismatch`).
   `rerun.py` also runs a `clock_check()` before every rep and supports `--redo-skewed`.
3. **X-Verified-Sub spoof does NOT succeed.** The `-bob`, lowercase `-case`, and `X_Verified_Sub`
   `-underscore` variants do **not** reach the executor on any gateway. Only `g3-xverified-sub-alice`
   and `-dup` "propagate", and their marker is `alice` — the *legitimate* verified subject the
   gateway set. That is a false positive of the §8 predicate (marker == legit value), identical to
   `kill` artefact #4, not an identity spoof. All three gateways correctly overwrite X-Verified-Sub.
4. **RC-W13-A resource severity.** S1 per oracle_spec §5 ("different `{id}`"). The executed id is
   `%2facc-alice-1` (aspnet/go-chi) or `/acc-alice-1` (express/rails) — a *different* resource than
   the proof-bound `acc-alice-1`. Whether it maps to another real row depends on the backend's own
   decoding; the binding violation (verifier view ≠ executed op) is unconditional. ddmin (§7)
   reduces it to the single `%2f` edit.
5. **Transport errors.** 2 / 91,008 cases returned status 0 (connection reset), both **non-hit**
   cases (apisix-recommended-django `g3-sub-alice`; haproxy-laravel `g2-xforwarded-prefix`). No hit
   is affected.
6. **Uncorrelated executor records** (`jti=null`): the orchestrator health probe's direct calls;
   not hits (oracle reports them separately).
7. **G3 propagation is conditional.** RC-W13-C/D are spoofable-header-crosses-boundary findings, not
   binding-resolution hits. They become authz-soundness violations only in a deployment whose
   backend trusts those headers. Reported as disclosure candidates, not counted in the 1368.

## 6. What this adds to the project

- **1 new independent G2 binding-resolution class** on current releases in default **and**
  recommended config: **RC-W13-A (APISIX `%2f` view/execution split)** — exactly the "does APISIX
  forward the raw or the normalised path upstream?" question in the brief. Answer: it sends the
  **normalised** path to the auth check and the **raw** path upstream.
- RC-W13-B extends `kill` RC6 (fragment) to Kong, APISIX and the laravel executor.
- RC-W13-C/D extend `kill`'s G3-propagation class to all three gateways (and show HAProxy/Kong,
  unlike APISIX, forward a forged D-B MAC).
- **HAProxy is the clean stack**: zero G2, because it uses a single URI representation for the auth
  view and the upstream request. Its recommended `normalize-uri` is sound defence-in-depth.

## 7. ddmin — minimal witness per distinct root cause

Each minimised against a **live** topology (oracle_spec §10 delta-ddmin over target/header/body
units); every result `still_hit=True`. Files: `ddmin/*.json`.

| root cause | topology | full→min units | minimal request (first line) | reading |
|---|---|---|---|---|
| **RC-W13-A** `%2f` (G2) | apisix aspnet off | 3 → **3** | `DELETE /api/v1/accounts/%2facc-alice-1` | irreducible: all 3 bytes of `%2f` are needed to encode the slash |
| **Kong fragment** (G2, = RC6) | kong fastapi off | 5 → **5** | `DELETE /api/v1/admin/users/u-1#frag` | irreducible: the `#frag` must sit in the **path** |
| **APISIX "fragment"** | apisix fastapi off | 5 → **1** | `POST /…/actions?op=freezeg` | **collapses to one extra byte in the `op` value** → this is query dispatch (= `kill` RC7), **not** a path view/execution split. See correction below. |
| G1 query dispatch | apisix aspnet off | 4 → 4 | `POST /…/actions?op=close` | `?op=close` (query not in htu) |
| G1 body dispatch | apisix aspnet off | 6 → 6 | `POST /api/v1/graphql` | JSON `operationName` (body not covered) |
| G1 method override | kong fastapi on | 1 → **1** | `DELETE /…/acc-alice-1` + `X-HTTP-Method-Override: GET` | the single override header (= `kill` RC5) |

**Correction from ddmin (skepticism).** The oracle statically tags the `g2-fragment` primitive as
G2, but ddmin shows the **APISIX** fragment hits (12, dispatch form, `accountAction.*`) minimise to
a single extra byte in the `op` query value — they are a **G1 query-dispatch effect (`kill` RC7)**,
where the `#…` lands in the query, not the path; the verifier allows because htu ignores the query.
They are **not** a genuine interpretation differential. The genuine **fragment-in-path G2** is the
**Kong** form only (resource, 72 hits), which reproduces `kill` RC6. Net genuine G2 binding-resolution
hits = **168** (apisix `%2f` 96 + kong fragment 72); the remaining 12 oracle-labelled-g2 are RC7/G1.
This does not change the class count: RC-W13-A (new, G2), RC-W13-B/Kong fragment (= RC6, G2),
RC-W13-C/D (G3 propagation).

## 8. Candidate disclosures
See `FINDINGS.csv`. Lead candidate: **APISIX forward-auth URI normalisation split** (RC-W13-A).
No vendor was contacted. Check each project's tracker for prior reports before any disclosure.
