# Root-cause notes — W14 (remaining frameworks + origin placement)

Scope: `binding/experiments/ext-fw`. 80 topologies, 948 depth-1 cases each (75,840 requests),
all real components (`--stubs off`), run 2026-11-23. Matrix:
- **(a)** {nginx, traefik, envoy} × {default, recommended} × placement=edge × {django, go-chi, rails, laravel} × override {off, on} = 48.
- **(b)** A3 ablation: {nginx, envoy} × profile=default × {origin, both} × all 8 frameworks × override on = 32.

Images: nginx 1.30.7-alpine, traefik v3.7.19, envoy v1.39.6, `bh-verifier:latest` (HTU_CANON=rfc3986,
JTI_CACHE=on, IAT_WINDOW=60), `bh-exec-{django,go-chi,rails,laravel,fastapi,express,spring,aspnet}:latest`.

Every hit is grouped by the oracle_spec §9 signature. The seven root causes below mirror the kill
experiment's RC1–RC7 and extend them to the four new frameworks and to origin/both placement.

Framework/server version facts (from the W4/W5 executor READMEs and the images):
- django: W4 ASGI image; go-chi: Go `net/http` + chi router; rails: Rack 3.2.9 / Puma 8.1.2 / Ruby 3.3.14;
  laravel: Laravel 12 + symfony/http-foundation 7.4.23 / PHP 8.3.37 / FrankenPHP 1.14.0 (Caddy).
- fastapi: uvicorn 0.54.0 + h11 0.16.0 (no httptools), starlette 1.10.0 (same image W9 used).

---

## RC1 query-parameter dispatch (G1, by design)
- Signatures: `g1-op-freeze-to-close`, `g1-op-freeze-to-unknown`, `g1-op-remove`, `g1-op-case-close`, `g1-op-dup-close`.
- Where: all 48 edge topologies and (origin) every envoy-origin topology; all 4 new frameworks, both overrides, both profiles.
- Mechanism: RFC 9449 §4.2 binds `htu` without query/fragment. The verifier accepts
  `POST /api/v1/accounts/acc-alice-1/actions?op=close` under a proof for `…?op=freeze`; the app dispatches on `op`.
  - django `request.GET`, go-chi `r.URL.Query()`, rails `params[:op]`, laravel `$request->input('op')`.
  - HPP `op=freeze&op=close`: django (last → `close`), rails (last → `close`), laravel (last → `close`, PHP),
    go-chi (`r.URL.Query().Get` → **first** → `freeze`, so `g1-op-dup-close` is **not** a hit on go-chi; it is on django/rails/laravel, 36 topos).
- Class **G1**, severity **S1**. Default and recommended identical.

## RC2 JSON-body dispatch (G1, by design)
- Signatures: `g1-gql-to-deleteProfile` (S1), `g1-gql-to-unknown`, `g1-gql-null` (all 48), `g1-gql-dup-deleteProfile` (rails only, 12).
- Mechanism: DPoP does not cover the body. Swapping `operationName` selects `graphql.deleteProfile` under a `getProfile` proof.
  All four new frameworks read the raw JSON body regardless of Content-Type (rails `JSON.parse(request.raw_post)`,
  laravel `json_decode($request->getContent())`, django/go-chi read the raw body).
- Duplicate key `operationName` (inserted before the original): django/go-chi/laravel keep the **last** key (→ sound `getProfile`).
  Rails' `JSON.parse` keeps the last key too, but its `params` merge path surfaces the injected first value in this executor, so the
  dup-key variant reaches `graphql.unknown` on rails (12 topos). (Measured; matches the aspnet behaviour W9 saw with a different parser.)
- Class **G1**, S1/S2.

## RC3 content-type relabel (G1, by design, framework-dependent)
- Signature: `g1-ct-urlencoded` → `graphql.unknown`. Where: **go-chi, override on only** (6 topos).
  django/rails/laravel read the raw body irrespective of Content-Type, so relabelling does not lose `operationName` (sound).
  go-chi with override on: the `method-override` style form read consumes/!parses the relabelled body so dispatch falls to `unknown`.
- Class **G1**, S2. Steers dispatch away (to `unknown`), never to a chosen op.

## RC4 form `_method` body replaces the JSON body (G1, by design)
- Signatures: `g1-fmethod-{get,post,put,patch,delete}` → `graphql.unknown`.
- Mechanism: the primitive rewrites the body to `_method=X` (urlencoded). Dispatch loses `operationName` → `unknown`.
  With override **on**, frameworks that honour form `_method` on POST (rails, laravel) change the method POST→X, giving 404
  (no non-POST route at `/graphql`), so the only surviving fmethod hit with override on is `g1-fmethod-post`
  (+`g1-fmethod-get` where the override middleware ignores GET). This is a *body-content* effect, not a method override.
- Class **G1**, S2.

## RC5 header/body method override, decoupled from the proof method (G1; default-config for Rails & Laravel)
- **This is the task's "default-config framework-level method-override" result.** Measured precisely (join runner→executor by jti,
  `effective_method` vs proof `htm`):
  - **Laravel**: stock Laravel enables form method spoofing **unconditionally and has no off switch**
    (`Request::capture()`/`Kernel::handle()` call `enableHttpMethodParameterOverride()`; symfony/http-foundation 7.4.23
    `Request::getMethod()`). W5 models the stock default as `OVERRIDE=on`; `OVERRIDE=off` needs a one-line framework API
    (`Request::setAllowedHttpMethodOverride([])`). Under the stock default, `X-HTTP-Method-Override` (header, wins),
    `_method` (form, query, and JSON) all override, **but only when the real method is POST**.
  - **Rails**: W5's executor is a **full (non-`api_only`) Rails app**, so `Rack::MethodOverride` is in the default middleware stack
    (`OVERRIDE=on` keeps the stock stack; `OVERRIDE=off` = `config.middleware.delete Rack::MethodOverride`). It honours
    `_method` (form body) and falls back to `X-HTTP-Method-Override` (`rack-3.2.9/lib/rack/method_override.rb`,
    `ALLOWED_METHODS=%w[POST]`), **POST only**; `?_method=` in the query and JSON `_method` are NOT honoured.
  - **Measured decoupling** (rails/laravel, override on): a POST base op with proof `htm=POST` is executed as the spoofed verb, e.g.
    `POST /api/v1/accounts/acc-alice-1/actions` + `_method=DELETE` → `effective_method=DELETE`, and
    `POST …/actions` + `X-HTTP-Method-Override: PUT` → `effective_method=PUT`. The verifier bound `htm=POST`; the executor ran another verb.
  - **But no oracle hit results**, because the only POST routes in the bench API (`/actions`, `/transfers`, `/graphql`) share no path
    with a non-POST route, so POST→{GET,PUT,DELETE,PATCH} always lands on `NOT_FOUND` (404). This is the **RC5/§6 route-coverage gap**
    from the kill experiment, now confirmed for the two frameworks whose method override is on by default. The method binding gap is real;
    this route space cannot turn it into an executed op.
- **FastAPI** is different and DOES hit: its (W4) Flask-pattern `HTTPMethodOverrideMiddleware` overrides on **any** method, and
  `/api/v1/accounts/{id}` carries GET+PUT+DELETE. Under envoy-origin + override on, `GET …/{id}` + `X-HTTP-Method-Override: DELETE`
  executes `deleteAccount`, `GET→PUT` → `updateAccount`, etc. — the 6 `(method, route)` hits in `w14-envoy-default-origin-fastapi-ovon`.
  This is the only framework-level method-override **hit** and it is a config, not a default (FastAPI ships no override).
- Class **G1** (override not covered by `htm`), S1.

## RC6 `#` kept as a path character; verifier strips it as a fragment (G2)
- Signature: `g2-fragment` resource substitution on getAccount, getAccountV2, updateAccount, deleteAccount, adminDeleteUser, publicFile.
- Where: **nginx (default + recommended) × {go-chi, laravel}** = 4 topos × 6 ops × 2 overrides = 48 hits. (W9 had fastapi only.)
- Gateway step: nginx 1.30.7 accepts `#` in the origin-form request-target (RFC 9112 §3.2 forbids it) and, with bare
  `proxy_pass http://executor:8080;`, forwards `X-Original-URI: $request_uri` **with** the `#frag`. The verifier (RFC 3986) treats
  `#…` as a fragment, excluded by RFC 9449 §4.3 → **allow**.
- Framework step — three servers keep `#` as a path character, each for a different reason (measured `path_params`):
  - **go-chi** (Go `net/http`): `id = "acc-alice-1#frag"` (raw_target kept, `#` not a delimiter in the server's path parse).
  - **laravel** (FrankenPHP/Caddy): logs `raw_target = ".../acc-alice-1%23frag"` — Caddy **percent-encodes** `#` — and the router
    decodes it into `id = "acc-alice-1#frag"`.
  - (fastapi, from W9: uvicorn/h11 `partition(b"?")` keeps `#frag` in `path`.)
  - **django** strips it (URL resolver splits the fragment: raw_target has `#frag`, but `id = "acc-alice-1"`) → **sound**.
  - **rails** strips it (Puma/Rack: raw_target already `acc-alice-1`, no `#`) → **sound**.
  - traefik v3.7.19 and envoy v1.39.6 answer 400 to `#` in the path (no verifier record), so the resource variant is nginx-only.
- **Impact (skeptical, unchanged from W9):** the attacker can only append a suffix to the **last** path segment; the executed id is
  `<bound id>#<anything>`, never a chosen existing resource. Targeted probes (W9 `kill/ddmin/probe_fragment__*`) found no route/owner
  substitution in this route space. Classified **G2**, oracle severity S1 (resource), **practical severity low**.
- Default and recommended: both (nginx recommended adds nothing that rejects `#`).

## RC7 `#` in the query (G1 effect via the G2 vehicle)
- Signature: `g2-fragment` on accountAction.freeze → `unknown` (`op = "freeze#frag"`).
- Where: nginx × {go-chi, laravel} (query value keeps `#frag`) and **traefik × {go-chi, laravel}** (traefik rejects `#` in the path but
  forwards it inside the query) = the 1-per-topology g2 count on traefik. Because the query is unbound anyway (RC1), this adds **no
  resolution beyond RC1**. Counted as G1-effect.

## L1 (latent, no hit): dot-segments — unchanged from W9
- nginx (both profiles) and envoy default forward `/api/v1/accounts/./acc-alice-1` and `%2e` raw; the RFC-3986 verifier allows, all four
  new frameworks answer 404 (literal routers), so resolution stays 1. Traefik (`sanitizePath`) and envoy recommended (`normalize_path`)
  normalise first and are sound. Not counted toward the gate.

## G3 — no binding hit; propagation only
- **0 G3 binding hits** (no change of executed op) in any of the 80 topologies; the bench API does not act on trust headers.
- Propagation predicate (oracle_spec §8) fires on injected trust headers: S1 totals nginx 4264, traefik 1976, envoy 3029 across the
  frameworks. As W9 established, a large share are **oracle artefacts** (the `X-Verified-Sub: alice` marker equals the legitimate subject
  the gateway sets) and the rest are header pass-through (`X-Forwarded-Client-Cert`, `Client-Cert`) that matters only if a backend trusts
  them — a W6/W7 harness-config issue, not a vendor binding bug. Not counted toward the G2/G3 gate.

---

## A3 ablation (placement = origin / both) — see REPORT.md §A3
- **envoy-origin** (clean): origin-raw app-side verification does **not** remove the G1 differentials. Query/body dispatch (RC1–RC4)
  persist on all 8 frameworks (9–11 hits), and fastapi RC5 header override persists (19). Origin-raw binds the *raw* method and the htu
  without query/body, so exactly the by-design G1 gaps survive. It removes the G2 fragment hits only incidentally (envoy 400s `#`).
- **nginx-origin = 0 hits is a HARNESS ARTEFACT, not a defence.** nginx's default profile emits bare `proxy_pass http://executor:8080;`
  with no `proxy_set_header Host`, so nginx rewrites Host to `executor:8080`; the executor forwards `X-Original-Host: executor:8080`;
  the verifier reconstructs `http://executor:8080/...` ≠ proof `http://api.bench.test/...` → every request (even the sound baseline)
  denied `htu_mismatch`. The corrected run (`up_hostfix.py` adds `proxy_set_header Host $host;`) is in `runs_a3host/` and reproduces the
  envoy-origin result. See REPORT §A3.
- **both = 0 hits (nginx AND envoy) is a HARNESS ARTEFACT, not a defence.** `both` calls the single JTI_CACHE=on verifier twice per
  request; the edge call consumes the jti (recorded on allow, oracle_spec §10), so the executor's origin-raw call to the same verifier is
  denied `jti_replay` — including every sound baseline (606/948). DPoP's one-time `jti` makes "verify at edge AND origin against one
  stateful verifier" self-defeating; `both` therefore measures the replay cache, not binding.
