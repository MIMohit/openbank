# Disclosure triage — novelty and prior-art (W16)

Scope: every disclosure candidate from the project's experiments
(`binding/experiments/{kill,ext-gw,ext-routes,e4,ext-fw}`). Read-only web
research + local inspection of measured evidence; **no vendors contacted, nothing
posted publicly, no git commits**. All dates and URLs verified 2026-11-23.

**Framing for all G1 items:** RFC 9449 §4.2/§4.3 defines the DPoP bound view
`(htm, htu)` *without* query, body, or fragment, and without a method-override
header. Query/body/method-override dispatch ("G1, under-binding by design") is
therefore **DOCUMENTED-BEHAVIOUR of the DPoP spec itself**, not a vendor defect;
it is not vendor-disclosable and is omitted from the candidate table below except
for method-override, noted at the end. The triage below covers the G2
interpretation-differential candidates named in the task.

## Classification counts

| Classification | Count | Items |
|---|---|---|
| NEW | 1 | APISIX `forward-auth` encoded-slash view/execution split (RC-W13-A) |
| KNOWN-UNFIXED | 3 | `#`-in-request-target kept/encoded by uvicorn-h11, Go net/http (go-chi), FrankenPHP/Caddy (kill RC6; ext-routes X1/X2; ext-fw W14-F1/F2) |
| DOCUMENTED-BEHAVIOUR | 6 | Kong raw-`$request_uri` authz view split (RC2/RC7); ASP.NET/Kestrel dot-segment pre-route resolution (RC1); Spring matrix-param strip (RC5); Rails `//` squeeze (RC6-fw); case-insensitive routing ASP.NET/Express (RC3/RC4); dot-segment catch-all `{path:path}` (ext-routes X3) |
| KNOWN-FIXED-IN-LATER-VERSION | 0 | — (APISIX `forward-auth` line unchanged since 2022; see note) |
| OUT-OF-SCOPE | — | nginx `#`/`%2f` forwarding (enabler, not a vuln on its own); gateway-overwritten `x-verified-*`/`x-forwarded-*` echoes (G3 artefact, 0 independent classes) |

Drafts written for the 1 NEW + 3 KNOWN-UNFIXED items: `drafts/`. No report is sent.

## Triage table

| Candidate | Component / version | Class | Classification | Key evidence URLs | Vendor policy / threat model | Recommended action | What the paper may claim as new |
|---|---|---|---|---|---|---|---|
| **APISIX forward-auth decoded-view vs raw `%2f` upstream** (RC-W13-A) | apache/apisix:3.21.0-debian, `forward-auth` plugin | G2 | **NEW** (pending 1 in-code check, draft §7) | [forward-auth.lua](https://github.com/apache/apisix/blob/3.21.0/apisix/plugins/forward-auth.lua); [APISIX security](https://security.apache.org/projects/apisix/); adjacent [CVE-2021-43557](https://apisix.apache.org/blog/2021/11/23/cve-2021-43557-research-report/) | No CVE for this `forward-auth` view-split. Docs describe `X-Forwarded-Uri` as "the request as the client sent it" but don't address `%2f`/normalization. CVE-2021-43557 established that un-normalized `request_uri` in plugins is untrusted. | Draft private report (`drafts/apisix-forward-auth-encoded-slash.md`); **verify the exact `X-Forwarded-Uri` bytes locally before sending** (source uses `ctx.var.request_uri`, which should be raw — resolve the decode mechanism). | The DPoP-binding composition and the systematic cross-gateway measurement; the raw-view-vs-execution split class itself is prior art. |
| **`#` kept/encoded in request-target** → uvicorn-h11 / Go net/http / FrankenPHP-Caddy (kill RC6; ext-routes X1/X2; ext-fw W14-F1/F2) | uvicorn 0.54.0 + h11 0.16.0 (no httptools); go-chi (Go net/http); Laravel 12 / FrankenPHP 1.14.0; behind nginx 1.30.7 | G2 | **KNOWN-UNFIXED** | [uvicorn disc. #1222](https://github.com/encode/uvicorn/discussions/1222); [RFC 9112 §3.2](https://www.rfc-editor.org/rfc/rfc9112#section-3.2); same class fixed in [HAProxy CVE-2023-45539](https://git.almalinux.org/rpms/haproxy/raw/branch/c8s/CVE-2023-45539-reject-pound-char-URI-component.patch) | No security advisory/fix for uvicorn/h11, Go net/http, or Caddy keeping `#`. HAProxy treated it as a vuln and rejects `#`; Envoy v1.39.6 / Traefik v3.7.19 return 400 for `#` in the path. Go may consider rejection the proxy's job. | Draft low-severity reports (`drafts/uvicorn-…`, `…caddy-frankenphp-…`, `…go-nethttp-…`). | The verifier-view-vs-executed-path *composition*, and the nested-route **operation** change (`deleteAccount→deleteStatement`) on a default nginx+FastAPI/go-chi/laravel stack (ext-routes). The lenient `#` parsing itself is known. |
| **Kong raw-`$request_uri` authz view split**, `/../` and `//` (e4 RC2, RC7) | kong 3.9.5, forward-auth via `pre-function` `X-Original-URI=ngx.var.request_uri` | G2 | **DOCUMENTED-BEHAVIOUR** + KNOWN | [xvnpw Kong/NGINX (2021)](https://xvnpw.github.io/posts/path_traversal_in_authorization_context_in_kong_and_f5_nginx); [CVE-2021-27306](https://www.wiz.io/vulnerability-database/cve/cve-2021-27306) | Kong docs state `kong.request.get_path()`/`request_uri` are **not normalized**; the raw-variable-in-custom-auth hazard is documented since 2021. Post-CVE-2021-27306 Kong normalizes for its own routing, so the split (raw to PDP, normalized to router/upstream) is intrinsic to a user config that feeds the PDP the raw value. | **No new disclosure.** The config is the documented "custom plugin using un-normalized variables" case. Cite as known. | The DPoP composition only; the Kong behavior is documented and the class is prior art. |
| **ASP.NET/Kestrel dot-segment pre-route resolution** vs gateway policy (e4 RC1) | .NET 9.0.23 (Kestrel, minimal APIs) | G2 | **DOCUMENTED-BEHAVIOUR** + KNOWN | MS routing docs (match on resolved/decoded path); `experiments/W5 executors/aspnet/README.md`; class CVEs: Istio [CVE-2021-31920](https://www.wiz.io/vulnerability-database), OPA-Envoy CVE-2026-26205, Envoy 2019 GHSA | Kestrel resolves dot-segments before routing per docs; each component behaves per its own spec. The defect is the *composition* with a raw-view external PDP. | **No new disclosure** (per task: do not contact vendors; components behave per docs). Mitigation evidence captured in `e4/native` (E4-N1/N2). | The composition finding: that it defeats even a strict default-DENY allowlist across 3 gateways; and the binding-soundness framing. |
| **Spring matrix-param strip** `;` (e4 RC5) | Spring Boot 3.5.16 / spring-web 6.2.19 (Tomcat, PathPatternParser) | G2 | **DOCUMENTED-BEHAVIOUR** | Spring matrix-variables reference docs; `W5 executors/spring/README.md` (pre-flagged this exact vector) | Spring strips matrix params (`;…`) for matching by design. The bug is a path-literal deny-regex that doesn't account for `;`. | **No new disclosure.** Policy-authoring antipattern, not a vendor vuln. | Composition / binding-soundness claim; the Spring behavior is documented. |
| **Rails `//` squeeze** (e4 RC6, ext-fw) | Rails 8.1.4 (ActionDispatch on Puma) | G2 | **DOCUMENTED-BEHAVIOUR** | Rails `ActionDispatch` `normalize_path` (`path.squeeze!('/')`); `W5 executors/rails/README.md` | Rails collapses repeated slashes by design. Bug is a deny-regex not matching the un-squeezed path. | **No new disclosure.** | Composition claim only. |
| **Case-insensitive routing** ASP.NET / Express (e4 RC3, RC4) | .NET 9.0.23; express 4.22.3 (path-to-regexp 0.1.13) | G2 | **DOCUMENTED-BEHAVIOUR** | MS routing docs (case-insensitive); Express `case sensitive routing` off by default | Both route case-insensitively by default. Bug is a case-sensitive deny-regex (`^/api/v[12]/admin`) that misses `/ADMIN`. | **No new disclosure.** Lesson: deny-regexes must fold case. | Composition claim: case-fold deny-regex vs case-insensitive router. |
| **Dot-segment catch-all** `{path:path}` (ext-routes X3) | fastapi/go-chi/laravel etc. v2 catch-all route + RFC-3986 verifier | G2 | **DOCUMENTED-BEHAVIOUR** / by-design | RFC 3986 §6.2.2.3 (verifier removes `./`); catch-all captures raw segment by design | Catch-all routes deliberately capture the raw remaining path; verifier normalizes per RFC 3986. No vendor defect. Practically low (only no-op `./` passes; every `..` is denied by the verifier). | **No new disclosure.** | New *realisation* that the (previously latent) dot-segment differential becomes an executed op via a catch-all route. |
| nginx forwarding raw `#` / `%2f` (kill F2; enabler) | nginx 1.30.7-alpine | enabler | **OUT-OF-SCOPE** | nginx `$request_uri`/`proxy_pass` docs | Long-standing lenient behavior; nginx routes on its own normalized `$uri`. Not a vuln on its own. | None. | n/a |

## Method-override (G1) note

ext-routes X4/X5 and kill RC5: a leaked `postAccount` (POST) proof becomes
PUT/DELETE via standard method-override middleware (`_method` body, or
`X-HTTP-Method-Override`). This is **DOCUMENTED-BEHAVIOUR** of the middleware
(Rails `Rack::MethodOverride` and Laravel Symfony `_method` are in the *default*
middleware; FastAPI/Flask override is opt-in), and the method is uncovered by the
DPoP view per RFC 9449. Prior art: golinelli2026post ("When POST Becomes GET",
method interchange) and grpc-gateway CVE-2026-37236 (override bypasses
upstream method ACLs). Not vendor-disclosable; cited in the paper's G1/related
work (see `binding/lit/novelty_memo.md`).

## Version currency (task step 2)

- **apache/apisix 3.21.0** — near-current (3.18.0 released 2026-08-20; 3.21.0 is
  later). The `forward-auth.lua` `X-Forwarded-Uri` line is unchanged from the
  2022 original commit through `master`, so **not fixed in any later version**.
- **kong 3.9.5** — superseded (3.16.0.0 released 2026-09-15; Kong Enterprise
  3.9.x EOL 2026-01-20). The behavior is a user-config choice (feeding the PDP a
  raw variable), not version-specific.
- **.NET 9.0.23** — .NET 10 is GA (since 2025-11); Kestrel dot-segment resolution
  is unchanged and documented.
- **nginx 1.30.7, Spring Boot 3.5.16, Rails 8.1.4, express 4.22.3** — the
  relevant behaviors are documented and stable across versions; currency is not
  material to the classification.

## What the paper may claim as new (consolidated)

1. The **oracle**: acceptance of a sender-constraint proof (DPoP) measured
   against the *executed operation* across layered deployments (see
   `lit/novelty_memo.md` RQ-L1 — no prior work does this).
2. The **systematic cross-product**: gateways × frameworks × profiles ×
   override, with ddmin-minimized, determinism-checked results.
3. **RC-W13-A** (APISIX forward-auth encoded-slash split) is the one candidate
   with a plausible claim to a *new vendor-relevant* finding, pending the §7
   verification; even so, the novel contribution is the binding composition.
4. The **nested-route operation change** under default config (ext-routes X1):
   the first result where a pure G2 interpretation differential (not app
   dispatch) produces an *operation* change on a documented, default stack.

Everything else (Kong/ASP.NET/Spring/Rails/case-fold/dot-segment-catch-all) is a
**composition** of individually documented behaviors and must be framed that way;
the individual component behaviors are prior art or vendor-intended.
