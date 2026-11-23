# ext-gw root causes (W13)

Gateways: kong, apisix, haproxy. Profiles default+recommended, placement edge, 8 frameworks,
override off/on = 96 topologies. All runs `--stubs off`. Docker clock skew 0 s at rerun time;
zero `iat_skew`/expired denials in any of the 96 verifier logs (all 14 640 denials are
`htu_mismatch`), so no clock artefact (cf. W9).

## Config facts (from harness/gateways/*/rendered/{default,recommended}-edge)

- **Kong** (`kong.yml`): `pre-function` Lua calls `/authz/orig` with
  `X-Original-URI = ngx.var.request_uri` (the RAW request target). `strip_path:false`.
  default `preserve_host:false`, recommended `preserve_host:true` — the ONLY config
  difference, and it changes no hit (Host is not in the binding view here).
- **APISIX** (`apisix.yaml`): `forward-auth` plugin → `/authz/fwd`. default-edge and
  recommended-edge are **byte-identical**. The auth subrequest view comes from
  `X-Forwarded-Uri`, which APISIX fills with the **decoded/normalised** path (nginx `$uri`),
  while the upstream proxy keeps the **raw** request target.
- **HAProxy** (`haproxy.cfg` + `bh_authz.lua`): Lua calls `/authz/orig` with
  `X-Original-URI = txn.f:url()` and proxies the SAME parsed URI upstream — one
  representation, no view/execution split. default has NO `normalize-uri`; recommended adds
  `normalize-uri fragment-strip|path-strip-dotdot|path-merge-slashes|percent-decode-unreserved|
  percent-to-uppercase` and `http-restrict-req-hdr-names delete`. Hits are identical in both
  profiles (the default already has no split to exploit).

default == recommended for all **48** non-empty (gw,fw,ov) hit-count triples (0 mismatches).

## Headline (fresh analysis over all 96 runs — the 12:59 analysis was STALE, missed laravel)
- 96 topologies × 948 depth-1 cases = **91,008** raw requests, **2** transport errors (status 0,
  both non-hit cases: apisix-recommended-django g3-sub-alice, haproxy-laravel g2-xforwarded-prefix).
- verifier **allow 65,344 / deny 14,640** (every deny = `htu_mismatch`; zero iat_skew/expired).
- raw hits **1368**: S1 768, S2 600, S3 0. class **g1 1188, g2 180, g3 0**.
- G2 180 = apisix 108 (pct2f 96 + fragment 12), kong 72 (fragment). RC-W13-A pct2f: apisix,
  fw aspnet/express/go-chi/rails. RC-W13-B fragment: apisix dispatch + kong resource, fw
  fastapi/go-chi/**laravel**.
- resolution res_hat over 96×13=1248 pairs: {1:876, 2:162, 3:204, 4:6}.

## G1 (by design, = kill RC1/RC2/RC5, reproduced on all 3 gateways)
Query dispatch (`g1-op-*`, `?op=`), body dispatch (`g1-gql-*`, `operationName`), content-type
(`g1-ct-*`), and method override (`g1-fmethod-*` body `_method`, `g1-hdr-xhmo-*` header,
override=on only). All `dispatch` or `method+route`; the proof's (htm,htu) still matches the
canonical view, RFC 9449 §4.2/§4.3 concedes query/body/override are uncovered. Uniform across
kong/apisix/haproxy, both profiles. Not a gateway interpretation differential.

## G2 interpretation differentials (verifier view != executed operation)

### RC-W13-A  APISIX encoded-slash view/execution split  [NEW, independent]
- primitive `g2-pct2f-before-last`, deviation `resource`, S1, n=96 hits.
- gw=apisix, BOTH profiles, override off+on, frameworks **go-chi, express, aspnet, rails**
  (NOT fastapi/django/spring/laravel — their routers decode/reject `%2f` → 404).
- Mechanism (confirmed end-to-end, jti 3d6f96b1…):
  verifier (adapter=fwd) `view_uri=/api/v1/accounts/acc-alice-1` (DECODED) → htu matches base
  → `allow sub=alice`; executor raw_target `/api/v1/accounts/%2facc-alice-1`,
  `path_params.id="%2facc-alice-1"`, op_id=deleteAccount, 200. Proof bound to `acc-alice-1`,
  executor acts on a different resource id (`%2f`→`/` after decode). Binding resolution ≥2.
- Root cause: APISIX `forward-auth` sends nginx `$uri` (percent-decoded, normalised) in
  `X-Forwarded-Uri`, but the proxy forwards the raw `$request_uri` upstream. The classic
  view/execution split the task flagged. Kong does NOT hit this: it sends `ngx.var.request_uri`
  (raw) to the verifier, so the verifier sees `%2f` too and denies (`htu_mismatch`).
  Cite: APISIX forward-auth plugin (apache/apisix apisix/plugins/forward-auth.lua) +
  nginx `$uri` vs `$request_uri` semantics.

### RC-W13-B  Fragment view/execution split  [= kill RC6, reproduced on Kong & APISIX]
- primitive `g2-fragment`. Two observable forms:
  - Kong, deviation `resource`, n=48, fw fastapi/go-chi: `#frag` kept in path `{id}` by the
    executor's HTTP parser (uvicorn/h11, go net/http) → deleteAccount/getAccount/... on
    `acc-alice-1#frag`. Kong sends raw `request_uri` (incl. `#frag`) to the verifier, which
    strips the fragment (HTU_CANON=rfc3986) → allow; executor keeps it.
  - APISIX, deviation `dispatch`, n=8, fw fastapi/go-chi: verifier view `?op=freeze`
    (fragment dropped by `$uri`), executor sees `op=freeze#frag` → `accountAction.unknown`.
- Same root cause family as the NGINX fragment finding (kill RC6): gateway forwards `#` and
  the executor HTTP server does not strip it. NOT counted as a new independent class.

## G3 binding propagation (propagation.jsonl; predicate = spoofed MARKER value observed at executor)

### Identity header X-Verified-Sub — NO genuine spoof
The `-bob`, `-case` (lowercase), `-underscore` X-Verified-Sub variants do **not** reach the
executor on any gateway. Only the `-alice`/`-dup` variants "propagate", and their marker is
`alice`, which is the LEGITIMATE verified subject the gateway set — a false positive, not a
spoof. All three gateways correctly overwrite/strip client X-Verified-Sub. (Skeptic check paid
off.)

### RC-W13-C  mTLS client-identity header propagation  [NEW; kill found zero G3]
Spoofed `Client-Cert` / `X-Client-Cert` (+case/underscore) and `X-Forwarded-Client-Cert`
(inject/case/dup/underscore) with attacker SPIFFE `sa/admin` / fake cert reach the executor
UNSTRIPPED on **all three gateways**, both profiles. Marker is clearly forged (not a legit
value). Authorization-soundness violation in any deployment that trusts mTLS client-identity
headers at the backend (Istio CVE-2021-31920; RFC 9440 Client-Cert). Underscore variant only
survives on a few (26) — HTTP/1.1 header-name rules.

### RC-W13-D  Defence D-B view-MAC propagation (X-Verified-View)  [variant of RC-W13-C]
Forged `X-Verified-View: v1;<not-a-real-mac>` reaches the executor on **Kong (416)** and
**HAProxy (416)** but NOT APISIX (0 — forward-auth `upstream_headers` only copies the auth
response's value and drops the client's). Defeats defence D-B if the executor trusts the header
without re-verifying the MAC. Same root cause as RC-W13-C (no inbound trust-header stripping).

## Counting (gate §12) — honest novelty framing vs kill
kill already observed: RC6 (NGINX fragment, G2 binding hit) and the G3 trust-header
propagation class (117 findings/topology incl. XFCC/Client-Cert; F3 = X-Verified-View on
Envoy), the latter NOT counted as a binding hit.

ext-gw distinct G2/G3 classes observed = **3**:
1. **RC-W13-A  APISIX %2f view/execution split (G2)** — NEW. A genuine binding-resolution > 1
   hit (verifier allows decoded view, executor acts on raw `%2f` id), 96 hits, confirmed 3/3,
   current releases, default AND recommended, 4 frameworks. Not present on any of the 6 gateways
   in kill. **This is the 1 new independent G2 binding-resolution class ext-gw contributes.**
2. **RC-W13-B  fragment view/execution split (G2)** — reproduces kill RC6 on Kong & APISIX
   (new gateways). Same root cause family; not a new class.
3. **RC-W13-C/D  trust-header propagation (G3)** — reproduces kill's G3-propagation class on
   kong/apisix/haproxy (client-cert/XFCC on all three; X-Verified-View on kong+haproxy).
   Authz-soundness violation only under the "backend trusts the header" assumption; NOT a
   binding-resolution hit in this harness (consistent with kill treating it as conditional).

**worker_done count: 3 distinct G2/G3 classes observed; 1 of them NEW and independent
(RC-W13-A, a G2 binding-resolution hit). The other 2 reproduce kill's RC6 and G3-propagation
class on the three new gateways.**
