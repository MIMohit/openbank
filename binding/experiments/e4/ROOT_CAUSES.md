# E4 root causes — authorization-soundness differentials (W12)

The 325 confirmed violations across 50 topologies fall into **7 independent
authorization-soundness classes**, each a distinct *(resolving component, parsing
differential)* pair. All 7 are **G2 interpretation differentials** (the PDP and the
router read the same path differently). **0 are G3** (no trust-header propagation hit;
see §G3). Every class is on a **current release under a default or documented
configuration**, exceeds the CONTRACT §12 hard-kill threshold of ≥2, and was re-run 3× on
fresh topologies (`reruns/`).

An **authorization-soundness violation** (oracle `e4_oracle.py`, CONTRACT §6 reuse): the
PDP **allowed** alice (`verifier.jsonl decision=allow`, `sub=alice`) **and** the executor
acted on a resource/op she is forbidden — an `admin*` op, or a path param whose **decoded**
value is **exactly** `acc-bob-1` — with `status < 400` and `denied=false`. Severity **S1**
throughout (owner-crossing or admin, all state-changing or cross-tenant reads).

The differential is always between two views of one wire path:
* the **PDP view** `v(r)` = the raw request target the gateway reports to the auth adapter
  (`X-Original-URI = $request_uri` for nginx/kong/haproxy origin-mode, the raw forwarded
  URI for Traefik/APISIX, the request path for Envoy ext_authz) — this is also the path the
  DPoP `htu` is bound to, so alice's minted proof always passes; and
* the **execution path** = what the backend router actually matches after the gateway and/or
  framework normalise it.

Two sub-mechanisms produce the gap:
* **framework-resolved** (`resolved_by=framework`): the gateway forwards the *raw* path to
  **both** the PDP and the executor; the backend framework normalises it. Backend-specific.
* **gateway-resolved** (`resolved_by=gateway`): the gateway reports the *raw* path to the
  PDP but **normalises the path it proxies upstream**; the executor sees a clean path.
  Backend-independent (fires for every framework).

Image versions (read from the running images / topology YAML, run 2026-11-23):
gateways nginx 1.30.7-alpine, traefik v3.7.19, envoy v1.39.6, kong 3.9.5,
apache/apisix 3.21.0-debian, haproxy 3.2.27; frameworks ASP.NET Core/.NET 9.0.23 (Kestrel),
Express 4.22.3 (path-to-regexp 0.1.13), Spring Boot 3.5.16 / spring-web 6.2.19 (Tomcat,
PathPatternParser), Rails 8.1.4 (actionpack, Puma), Laravel 12.73.0 (FrankenPHP),
FastAPI 0.165.0 / Starlette 1.10.0 / uvicorn 0.54.0. PDP `bh-pdp-{allow,block}:latest`
(real `verifier.core` + path policy).

---

## E4-RC1 — ASP.NET Core / Kestrel resolves `/../` before routing (framework, G2)

* **Vectors:** `dotseg-*`, `encdotseg-*` (`%2e%2e`). **Policy:** allowlist **and** blocklist.
  **Profile:** default **and** recommended (nginx, haproxy); default only on envoy
  (envoy's recommended `normalize_path`/`merge_slashes` resolves it at the edge — see §Defences).
  **Where:** nginx, envoy, haproxy (the gateways that forward the raw target upstream).
  **Kinds:** admin + bob. **Severity:** S1. **n_topologies:** 10.
* **Mechanism.** PDP view = `/api/v1/accounts/acc-alice-1/../../admin/users/u-1`. The
  **allowlist** prefix rule `allow-v1-own` (`/api/v1/accounts/acc-alice-1`) matches the raw
  path's *prefix* → **ALLOW**. The **blocklist** `deny-admin`/`deny-foreign-account` regexes
  are anchored at `^/api/v[12]/(admin|accounts/…)` and never fire on a path that starts with
  alice's own account segment → default **ALLOW**. Kestrel then **resolves the dot segments
  in the decoded path before routing** → `adminDeleteUser` / `getAccount(id=acc-bob-1)`.
  The gateway forwarded the raw dotted target to the executor (`raw_target` still carries
  `/../`).
* **This is the headline class that defeats the *strict* default-DENY allowlist** — the
  strongest, recommended policy style — on three major gateways under their recommended
  profiles (nginx/haproxy).
* **Citation.** W5 `executors/aspnet/README.md`: "`/../`, `%2e%2e`, `/./` **resolved by
  Kestrel** before routing … `/api/v2/../v1/admin/users → adminListUsers`. Kestrel
  normalises dot segments in the decoded path. `raw_target` keeps the original." Microsoft
  routing docs: "Text matching is … based on the decoded representation of the URL's path"
  (https://learn.microsoft.com/en-us/aspnet/core/fundamentals/routing).

## E4-RC2 — Kong normalises the upstream path but authorizes on the raw target — `/../` (gateway, G2)

* **Vectors:** `dotseg-*`, `encdotseg-*`. **Policy:** allowlist **and** blocklist.
  **Profile:** default **and** recommended. **Where:** kong, **all six frameworks**
  (fastapi, express, spring, aspnet, rails, laravel). **Kinds:** admin + bob. **Severity:**
  S1. **n_topologies:** 16.
* **Mechanism.** Kong's forward-auth (rendered by W6 `gateways/kong/render.py`) sets
  `X-Original-URI = ngx.var.request_uri` — the **raw** wire target, exactly as CONTRACT §3
  requires for an "original URI" check and exactly what the DPoP `htu` is bound to. The PDP
  therefore sees `/api/v1/accounts/acc-alice-1/../../admin/users/u-1` and **allows** it
  (prefix match / regexes miss, as in RC1). Kong then **resolves the dot segments in the
  path it proxies upstream** (`$request_uri` raw ≠ the normalised proxy path in
  OpenResty/Kong), so the executor receives a clean `/api/v1/admin/users/u-1`
  (`raw_target` is already normalised at the executor). Fires identically for every
  framework → **backend-independent**.
* **The second headline class that defeats the strict allowlist**, and the only one that is
  framework-independent. It is an *internal* inconsistency of the gateway: its auth view and
  its proxy path disagree.
* **Citation.** Captured config `runs/w12-allow-kng-*/generated/gateway/kong.yml`
  (`["X-Original-URI"] = ngx.var.request_uri`). nginx variable semantics: `$request_uri` is
  "the full original request URI (with arguments)", un-normalised, vs the normalised `$uri`
  (https://nginx.org/en/docs/http/ngx_http_core_module.html#var_request_uri). Kong path
  handling resolves `.`/`..` segments before upstream proxying
  (https://docs.konghq.com/gateway/latest/how-kong-works/routing-traffic/).

## E4-RC3 — ASP.NET Core routes case-insensitively (framework, G2)

* **Vectors:** `case-admin-del`, `case-admin-list` (`/api/v1/ADMIN/users…`),
  `case-api-admin` (`/API/V1/admin…`). **Policy:** blocklist. **Profile:** default +
  recommended. **Where:** all six gateways (the uppercase path is forwarded raw). **Kinds:**
  admin. **Severity:** S1. **n_topologies:** 12.
* **Mechanism.** PDP view `/api/v1/ADMIN/users/u-1`. The blocklist `deny-admin` regex
  `^/api/v[12]/admin(?:/|$)` is **case-sensitive** and does not match `ADMIN` → default
  **ALLOW**. ASP.NET routing is case-insensitive → `adminDeleteUser`. (The allowlist is
  unaffected: its allow-rules also fail to match, so default-DENY correctly blocks — this is
  a blocklist-style failure only.)
* **Citation.** Microsoft routing docs (quoted above): matching is case-insensitive. W5
  `executors/aspnet/README.md`: case variants "**match** (case-insensitive)".

## E4-RC4 — Express routes case-insensitively (framework, G2)

* **Vectors:** `case-admin-del`, `case-admin-list`, `case-api-admin`. **Policy:** blocklist.
  **Profile:** default (express recommended topologies were out of scope — see Limitations).
  **Where:** all six gateways. **Kinds:** admin. **Severity:** S1. **n_topologies:** 6.
* **Mechanism.** Same as RC3: the case-sensitive `deny-admin` regex misses `ADMIN`, and
  Express (path-to-regexp 0.1.13, default `sensitive: false`) matches the route
  case-insensitively → `adminDeleteUser`.
* **Citation.** Express routing — route matching is case-insensitive unless `case sensitive`
  routing is enabled (https://expressjs.com/en/4x/api.html#app.set, `case sensitive routing`
  disabled by default); path-to-regexp `sensitive` defaults to false. W4
  `executors/express/README.md` (Express 4.22.3 / path-to-regexp 0.1.13).

## E4-RC5 — Spring MVC strips matrix (`;`) parameters for matching (framework, G2)

* **Vectors:** `matrix-admin-del`, `matrix-admin-list` (`/api/v1/admin;x=1/users…`),
  `matrix-accounts-bob` (`/api/v1/accounts;x=1/acc-bob-1`). **Policy:** blocklist.
  **Profile:** default + recommended. **Where:** all six gateways (the `;x=1` is forwarded
  raw). **Kinds:** admin + bob. **Severity:** S1. **n_topologies:** 12.
* **Mechanism.** PDP view `/api/v1/accounts;x=1/acc-bob-1`. The `deny-foreign-account` regex
  requires `^/api/v[12]/accounts/…` but the character after `accounts` is `;`, not `/`, so
  the regex does not fire; likewise `/api/v1/admin;x=1/…` dodges `deny-admin` → default
  **ALLOW**. Spring's PathPatternParser matches on path segments **without** their matrix
  parameters → `getAccount(id=acc-bob-1)` / `adminDeleteUser`.
* **Citation.** Spring matrix-variables reference: the parser matches path segments without
  their matrix parameters
  (https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-methods/matrix-variables.html).
  W5 `executors/spring/README.md` pre-flagged exactly this: "`DELETE /api/v1/admin;x=1/users/u-1
  → adminDeleteUser`, which is a G2 differential against any prefix-matching gateway or
  verifier." E4 demonstrates it end-to-end against a PDP.

## E4-RC6 — Rails collapses `//` (`squeeze`) before routing (framework, G2)

* **Vectors:** `dslash-accounts-bob` (`/api/v1//accounts/acc-bob-1`), `dslash-admin-del`,
  `dslash-admin-list`. **Policy:** blocklist. **Profile:** default + recommended.
  **Where:** nginx, envoy, haproxy (gateways that forward the doubled slash raw; see RC7 for
  Kong). **Kinds:** admin + bob. **Severity:** S1. **n_topologies:** 4.
* **Mechanism.** PDP view `/api/v1//accounts/acc-bob-1`. The `deny-foreign-account` regex
  requires a single `/api/v1/accounts/` and does not match the doubled slash → default
  **ALLOW**. Rails' `ActionDispatch::Journey::Router::Utils.normalize_path` does
  `path.squeeze!("/")` → `getAccount(id=acc-bob-1)`.
* **Citation.** W5 `executors/rails/README.md`: "`//` … **matches**: `/api/v1//accounts/x →
  getAccount` … `normalize_path` does `path.squeeze!("/")` (actionpack-8.1.4
  `journey/router/utils.rb`)."

## E4-RC7 — Kong collapses `//` upstream but authorizes on the raw target (gateway, G2)

* **Vectors:** `dslash-*`. **Policy:** blocklist. **Profile:** default + recommended.
  **Where:** kong, frameworks {aspnet, express, rails, spring}. **Kinds:** admin + bob.
  **Severity:** S1. **n_topologies:** 7.
* **Mechanism.** Same root as RC2 (raw auth view, normalised proxy path), with the
  double-slash primitive: PDP sees `/api/v1//accounts/acc-bob-1` and the blocklist regex
  misses it; Kong collapses the slash upstream → the executor sees
  `/api/v1/accounts/acc-bob-1` (clean `raw_target`) → `getAccount(id=acc-bob-1)`.
* **Citation.** As RC2 (kong.yml raw `$request_uri`; Kong normalises the proxied path).

---

## Vectors that did **not** hit (skepticism / conservative oracle)

* **`.json` suffix** (`json-admin-list`, `json-accounts-bob`), **trailing slash**
  (`trail-admin-list`): `pdp_denied` in all 96 runs each. The suffix/trailing `/` sits
  *after* the segment the deny-regex already anchored on, so the regex still fires; and the
  allowlist still default-denies. Null against both policy styles here (would matter only
  against an **exact-match** allow rule for a `.json`-bearing resource, which the battery
  does not contain).
* **`%2F` in `{id}`** (`encslash-bob-get`): never a clean violation — `allowed_other` /
  `exec_rejected` / `proof_rejected`. Tomcat (Spring) rejects `%2F` with 400; Laravel 404s on
  the decoded `[^/]+`; where it did route, the decoded param was **not exactly** `acc-bob-1`
  (e.g. `acc-alice-1/../acc-bob-1` kept verbatim), which the oracle **conservatively excludes**
  (it requires the decoded id to equal `acc-bob-1`). This is the harness being skeptical, not
  a missed hit.
* **`direct-*`** controls (unmutated forbidden requests) are denied/blocked everywhere;
  **`legit-*`** controls (alice's own resources) are allowed and sound everywhere — the PDP
  is neither over- nor under-blocking on the baseline.

## G3 (propagation) — not observed, and a coverage gap

No trust-header propagation hit occurred, consistent with W9's zero-G3 finding. **Caveat:**
the implemented A_client battery (29 vectors) does **not** include the absolute-form target
or the `X-Original-URL` / `X-Rewrite-URL` header-rewrite vectors the task listed; those are a
G3 probe left open (see `REPORT.md` §G3 probe / Limitations). The 7 classes above are all G2.

## Clock-skew / Docker-sleep artefact (the W9 warning)

Checked: across all 50 sweep runs the verifier/PDP emitted **zero** `iat`/skew/expired/future
denials (decision reasons were only `ok`, `policy_deny:*`, `auth_missing`, `htu_mismatch`).
The sweep ran on a non-skewed clock; no reps needed redoing for skew. `htu_mismatch` (148)
is the *expected* signal that normalising gateways (Traefik/APISIX/Envoy-recommended) rewrote
the path before the PDP so alice's `htu` no longer matched — i.e. those configs are **not**
vulnerable, which is why they are absent from the classes above.
