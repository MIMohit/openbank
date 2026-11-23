# Root-cause notes (W9 kill experiment)

The 680 raw hits from the 48 topologies fall into 30 cross-topology signatures (`analysis/signatures.csv`).
Those collapse into **7 root causes (RC1–RC7)** plus **1 latent differential (L1)** that never produced a hit.
Every hit of every RC was re-run 3× (`reruns/`: 680/680 confirmed). RC1, RC2, RC4, RC5, RC6 and RC7 were ddmin-minimised (`ddmin/`). RC3 was not: it is a single Content-Type header value.
"Gateway step × framework step" names the two parsing steps that disagree. For G1, the
disagreement is between the **verifier's bound view** (htm, htu: no query, no body, no override)
and the **application/framework dispatch input**.

Version facts were checked in the images: uvicorn 0.54.0, h11 0.16.0, starlette 1.10.0, fastapi 0.165.0 (no httptools);
express 4.22.3 + method-override 3.0.0; Spring Boot 3.5 / spring-web 6.2.19; ASP.NET Core (W5 README).

---

## RC1: query-parameter dispatch (G1, by design)
- Signatures: `g1-op-freeze-to-close`, `g1-op-freeze-to-unknown`, `g1-op-remove`, `g1-op-case-close`, `g1-op-dup-close`.
- Where: all 48 topologies, all gateways, both profiles, all frameworks, override off and on.
- Mechanism: RFC 9449 §4.2 defines `htu` without query and fragment. The verifier accepts `POST /api/v1/accounts/acc-alice-1/actions?op=close`
  under a proof for `…?op=freeze`. The application dispatches on `op`.
  - HPP variant `op=freeze&op=close`: FastAPI takes the **last** value (Starlette `QueryParams.__getitem__` returns the last), giving `close`.
    Express `qs` builds an array, Spring joins as `"freeze,close"`, and ASP.NET binds `"freeze,close"`, so all three give `unknown`.
    This is a framework-level difference in *which* op is reached. It does not change *whether* the binding gap exists.
- Gateway step: none. All three gateways forward the query unchanged, and the verifier view includes the query, which is then ignored per the RFC.
- Class **G1**, severity **S1** (state-changing action selected). Default and recommended: both.

## RC2: JSON-body dispatch (G1, by design)
- Signatures: `g1-gql-to-deleteProfile`, `g1-gql-to-unknown`, `g1-gql-null` (all 48), and `g1-gql-dup-deleteProfile` (aspnet only, 12).
- Mechanism: DPoP does not cover the body. Swapping `operationName` selects `graphql.deleteProfile` under a `getProfile` proof.
- Duplicate key: the primitive inserts `"operationName":"deleteProfile"` *before* the original key
  (`mutator/transforms.py:inject_duplicate_json_field`). Python `json`, `JSON.parse` and Jackson keep the last key, which is `getProfile`, so the request is sound.
  System.Text.Json `JsonObject` throws on a duplicate key (W5 aspnet README, row "graphql duplicate"), so the request falls to `unknown`.
- Class **G1**. Severity: S1 for `deleteProfile`, S2 for `graphql.unknown` (the oracle grades unknown graphql as a read).

## RC3: content-type switch (G1, by design, framework-dependent)
- Signatures: `g1-ct-urlencoded` on express (off/on), spring (off/on) and aspnet (**on only**); `g1-ct-textplain` on express (off/on). All → `graphql.unknown`.
- Mechanism: the JSON bytes are relabelled with another Content-Type, so the dispatch key is lost.
  - Express: `express.json()` only parses `application/json`, so `req.body` holds no `operationName` (measured).
  - Spring: the W5 handler reads the raw body whatever the CT. With `application/x-www-form-urlencoded`, Tomcat consumes the body to build the servlet parameter map as soon as
    something calls `getParameter` (here `@RequestParam`/filters, Servlet spec "When parameters are available"). The raw-body read then finds it empty.
    *This is an inference from the measured outcome. I did not trace it in the Spring source.*
  - ASP.NET with override on: the form-field `HttpMethodOverrideMiddleware` instance reads the form for a POST with a form CT, which consumes the body (also an inference). With override off it reads the raw body, which is sound.
  - FastAPI reads the raw body, so it is sound.
- Class **G1**, S2. It can only steer dispatch *away* (to unknown), not to a chosen op.

## RC4: form `_method` body replaces the JSON body (G1, by design)
- Signatures: `g1-fmethod-{get,post,put,patch,delete}` → `graphql.unknown`.
- Mechanism: the primitive rewrites the body to `_method=X` (urlencoded). With override off, nothing reads `_method`, and dispatch loses `operationName`, giving `unknown`.
  With override on, frameworks that honour form `_method` (express, spring, aspnet) change the method → 404, so fewer hits with override on. FastAPI's override reads only the header.
- Class **G1**, S2. This is a body-content effect, *not* a method override.

## RC5: header method override, any original method (G1, framework config)
- Signatures: `g1-hdr-xhmo-{get,put,delete}` on getAccount / updateAccount / deleteAccount ↔ each other.
- Where: **fastapi, override=on only**, all 3 gateways × 2 profiles (6 topologies × 6 signatures = 36 hits).
- Mechanism: the verifier binds `htm` = the request-line method. The executor's override middleware (W4's ASGI transliteration of Flask's
  documented `HTTPMethodOverrideMiddleware`, https://flask.palletsprojects.com/patterns/methodoverrides/) rewrites the method from
  `X-HTTP-Method-Override` for **any** original method, so `GET …` + `X-HTTP-Method-Override: DELETE` runs deleteAccount.
  None of the gateways strips the header, in either profile.
- Why not express/spring/aspnet: their standard mechanisms (`method-override` default `methods:['POST']`, `HiddenHttpMethodFilter`,
  `HttpMethodOverrideMiddleware`) only override **POST**. The bench API has no POST route that shares a path with another method
  (POST routes: `/accounts/{id}/actions`, `/transfers`, `/graphql`). So a POST→X override can only land on 404 here.
  **This is a bench-API coverage gap, not evidence of absence.** See G1_REPORT §6.
- Not a default config: all four frameworks ship override **off** (Spring Boot ≥ 2.2 property off; Express needs the middleware; ASP.NET needs `UseHttpMethodOverride`; FastAPI has none).
- Class **G1** (override not covered by htm), S1 (GET proof → DELETE executed).

## RC6: `#` kept in the path by uvicorn/h11, stripped by the verifier (G2)
- Signatures: `g2-fragment` resource substitution on getAccount, getAccountV2, updateAccount, deleteAccount, adminDeleteUser, publicFile.
- Where: **nginx (default + recommended) × fastapi (ov off/on)** = 4 topologies × 6 ops = 24 hits.
- Gateway step: NGINX 1.30.7 accepts a `#` in the origin-form request-target (RFC 9112 §3.2 does not allow it) and,
  with `proxy_pass http://executor:8080;` (no URI part), forwards the raw request URI unchanged
  (https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass). The auth subrequest receives `X-Original-URI: $request_uri`, the raw value with `#frag`.
- Verifier step: RFC 3986 parsing treats `#…` as a fragment, which RFC 9449 §4.3 excludes from the comparison, so the result is **allow**.
- Framework step: uvicorn 0.54.0's h11 protocol does `raw_path, _, query_string = event.target.partition(b"?")`
  (`uvicorn/protocols/http/h11_impl.py:204`, checked in the image), so `#frag` stays in `path`. Starlette's `{id}` converter
  (`[^/]+`) then binds `id = "acc-alice-1#frag"`. httptools is not installed. With httptools, uvicorn uses `httptools.parse_url`, which splits the fragment (not measured).
- Other frameworks: Express (Node `url` parsing) strips the fragment: `id = acc-alice-1`, sound.
  Tomcat (Spring) and Kestrel (ASP.NET) answer 400 to `#` (W5 READMEs), so they never execute. Traefik v3.7.19 and Envoy v1.39.6 answer 400 to `#` in the path (measured: no verifier record).
- Manual sanity check (oracle_spec §9): in each case the executor log line *and* the runner's parsed response body give the same `op_id`, and the
  handler returned 200 with `path_params.id = "acc-alice-1#frag"`. So the handler really ran, beyond just being logged.
  For createTransfer (`/api/v1/transfers#frag`) the path no longer matches the literal route: 404, not a hit.
- **Impact (skeptical):** the attacker can only append a suffix to the *last* path segment. The executed resource id is
  `<bound id>#<anything>`, not a chosen existing resource. In the bench API no route can be reached this way (targeted probes, see `ddmin/` and G1_REPORT §4).
  It becomes a real substitution only if the application then normalises the id (truncating at `#`, prefix lookup), or if there is a nested
  route `/{id}/<sub>` with the same method, e.g. `GET /accounts/{id}#/statements` → `GET /accounts/{id}/statements`
  (not present in the bench API). Classified **G2**, oracle severity S1 (resource), **practical severity low**.
- Default and recommended: both (the NGINX recommended profile adds nothing that rejects `#`).

## RC7: `#` in the query (G1 effect via a G2 vehicle)
- Signature: `g2-fragment` on accountAction.freeze → `unknown` (`op = "freeze#frag"`).
- Where: nginx × fastapi (4) and traefik × fastapi (4). Traefik rejects `#` in the path but forwards it inside the query.
- Mechanism: the same h11 partition behaviour. The query value becomes `freeze#frag`. Because the query is unbound anyway (RC1), this adds
  **no resolution beyond RC1**. Counted as G1.

## L1 (latent, no hit): the verifier removes dot-segments, the router does not
- `g2-dot-literal` (`/api/v1/accounts/./acc-alice-1`) and `g2-dot-enc` (`%2e`): **nginx default+recommended and envoy default** forward the raw
  target. The verifier (rfc3986 canon: remove_dot_segments, decode unreserved `%2e`) says **allow**, and all four executors answer **404 NOT_FOUND**
  (their routers match literally: Starlette, path-to-regexp, Spring PathPatternParser, ASP.NET routing). 468 allow→404 cases.
- This is a real verifier/router disagreement (G2), but in the bench route space the raw path maps to *no* route, so resolution stays 1.
  It would need a route that binds `.`/`..` literally (a catch-all/`{path:path}` parameter), which the bench API does not have.
  Envoy recommended (`normalize_path: true`) and Traefik (`sanitizePath: true`, default) normalise before both the verifier and the router, so they are sound.
- Not counted toward the gate. A follow-up targeted experiment is listed in G1_REPORT §6.

## G3
- **No G3 binding hit** (no change of executed op) in any of the 48 topologies. The bench API does not act on trust headers, so G3 can only show up
  as *propagation* (oracle_spec §8). That is reported separately and not counted for the gate.
- Propagation counts per topology: nginx and traefik 117, envoy 78. I checked them manually (getAccount, fastapi, default profiles):

| injected header | nginx | traefik | envoy | verdict |
|---|---|---|---|---|
| `X-Verified-Sub: bob` / `_` variant / `X-Verified-Jkt: <other>` | overwritten with the verifier's value | overwritten | overwritten | sound in all three (gateway config sets these from the authz response) |
| `X-Verified-Sub: alice`, `X-Verified-Sub` dup (alice,bob) | counted as propagation | counted | counted | **oracle artefact**: the marker `alice` equals the legitimate subject the gateway sets. The executor shows only the gateway's value. 26 of the 117/78 per topology (2 primitives × 13 ops) |
| `X-Forwarded-Client-Cert` (inject/case/dup) | forwarded | forwarded | **stripped** (Envoy HCM default `forward_client_cert_details: SANITIZE`) | real propagation through nginx/traefik. It matters only if a backend trusts XFCC |
| `Client-Cert`, `X-Client-Cert` | forwarded | forwarded | forwarded | a generic unknown header passes through. It matters only if a backend trusts it |
| `X-Verified-View` (spoofed D-B MAC) | removed (`proxy_set_header X-Verified-View $bh_view` with an empty var drops it) | removed (forwardAuth `authResponseHeadersRegex`) | **forwarded** | **relevant to D-B (W11)**: Envoy only *adds* `x-verified-*` from the ext_authz response. When the verifier emits no `X-Verified-View` (VIEW_MAC=off here), the client's spoofed value reaches the executor. With VIEW_MAC=on the authz response overwrites it. The executor-side D-B check must not trust the header unless the gateway is configured to strip client `x-verified-*` (e.g. `request_headers_to_remove`). This is a harness-config (W6) issue, not a vendor bug |

- Envoy recommended rejects the underscore variants (`headers_with_underscores_action: REJECT_REQUEST` → 400; 312 gw_reject cases).
