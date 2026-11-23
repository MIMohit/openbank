# E2: method override and dispatch features across web frameworks, and how often projects enable them

Worker W8. The machine-readable feature matrix is in `e2/out/E2_framework_features.csv`. The enablement counts are in `e2/out/code_search.csv` (run 2), `e2/out/code_search_run3.csv` (run 3), `e2/out/E2_enablement.csv` (ratios) and the raw API responses in `e2/out/code_search_raw.jsonl`. Every source line cited below refers to a file pinned at a release tag. `e2/verify_pins.sh` re-downloads all 20 pinned files from `raw.githubusercontent.com` and compares them byte for byte with our copies; the result was **20/20 IDENTICAL** (`e2/out/pin_verification.tsv`, 2026-11-23). `e2/check_docs.py` fetched every cited documentation page and confirmed it contains the phrase the claim relies on; the result was **19/19 found** (`e2/out/doc_checks.csv`, 2026-11-23).

## 1. Why method override matters for binding

A DPoP proof binds `htm`, the method on the wire. A method-override mechanism makes the **executed** method `m'` a function of a header, a body field or a **query parameter**. None of these is covered by the proof (G1). It also makes the method visible to an edge verifier (`POST`) differ from the method the router dispatches on (`DELETE`), which is a G2 split view. A proof for `POST /api/v1/accounts/{id}` then authorises `DELETE /api/v1/accounts/{id}` whenever the backend honours override and no `POST` route exists, or the `POST` route is a different operation.

## 2. Feature matrix (source and documentation verified)

| framework (pinned) | built-in? | default | value read from | reads **query**? | original method | allowed targets | source lines |
|---|---|---|---|---|---|---|---|
| Spring MVC: spring-framework v7.0.11, Boot v4.1.2 | yes, `HiddenHttpMethodFilter` | **OFF** since Boot 2.2 | `_method` via `request.getParameter` | **yes**, because `getParameter` merges the query string | POST | PUT, DELETE, PATCH | filter L57-58, L61, L81-86; Boot `WebMvcAutoConfiguration` L167-170 (`@ConditionalOnBooleanProperty("spring.mvc.hiddenmethod.filter.enabled")`); metadata `defaultValue: false` L40-43; Boot 2.2 release notes L195-197 ("disabled by default") |
| Spring WebFlux (same pins) | yes, reactive filter | OFF | `_method` form field | no | POST | PUT, DELETE, PATCH | reactive filter L49-53, L78-92; `WebFluxAutoConfiguration` L127 |
| ASP.NET Core v10.0.15 | yes, `HttpMethodOverrideMiddleware` | **OFF**, `app.UseHttpMethodOverride()` turns it on | `X-Http-Method-Override` header, or the configured form field | no | POST | **any string, with no allowlist** | middleware L15, L38-53, L60-67; options L17 |
| Express, `method-override` 3.0.0 (de-facto standard npm package) | separate package | OFF, `app.use(methodOverride(...))` turns it on | header `X-HTTP-Method-Override` by default; **any getter string not starting with `X-` reads the QUERY string**, so the common `methodOverride('_method')` reads `?_method=` | **yes** for `_method` | POST by default (`options.methods` can widen it) | any method Node knows, **including GET** | index.js L48-50, L53-55, L74-77, L100-105, L140-144 |
| FastAPI 0.165.0 / Starlette 1.10.0 | **no** | n/a | n/a | n/a | n/a | n/a | grep of the release tarballs found 0 non-test source files (`e2/out/tree_grep.txt`) |
| Django 6.1.3 | **no** | n/a | n/a | n/a | n/a | n/a | same, 0 files |
| Go net/http (stdlib) | no override; "a pattern with the method GET matches both GET and HEAD requests" | n/a | n/a | n/a | HEAD | dispatched to the GET handler | pkg.go.dev/net/http |
| Go chi v5.5.0 | no header or parameter override; the `middleware.GetHead` routing hook (`rctx.RouteMethod`) sends HEAD to GET handlers | OFF | n/a | n/a | HEAD | GET | context.go L53-56, mux.go L473-476, middleware/get_head.go L10-30 |
| Go gorilla/handlers v1.5.2 | yes, `HTTPMethodOverrideHandler` | OFF (wrapper) | `_method` via `r.FormValue` (**body or query**), then the header | **yes** | POST | PUT, PATCH, DELETE | handlers.go L121, L124, L127-146 |
| Rails v8.1.4.1 + Rack v3.2.6 | yes, `Rack::MethodOverride` | **ON by default**, removed only when `config.api_only = true` | `_method` body param, else the `X-HTTP-Method-Override` header | no (`req.POST` only) | POST | GET HEAD PUT POST DELETE OPTIONS PATCH LINK UNLINK | rack method_override.rb L9, L11-13, L19-26, L31-34, L48-49; railties default_middleware_stack.rb **L52** (`use ::Rack::MethodOverride unless config.api_only`) |
| Laravel v13.43.0 (requires symfony/http-foundation ^7.4 or ^8.0, composer.json L56) | yes, Symfony `Request::getMethod` | **ON, always**: `Kernel::handle` calls `$request->enableHttpMethodParameterOverride()` on every request | `X-HTTP-METHOD-OVERRIDE` header, else `_method` from **body or query** | **yes** | POST | anything except GET/HEAD/CONNECT/TRACE (deprecated in Symfony 7.4, ignored in 8.0) | Kernel.php **L142** |
| Symfony 6.4 (http-foundation v6.4.30) | yes | **header override ALWAYS on for POST**; the `_method` parameter is on if `framework.http_method_override` is unset (it defaults to true, with a deprecation) | header, else `_method` from body or query | yes | POST | GET HEAD POST PUT DELETE CONNECT OPTIONS PATCH PURGE TRACE, plus any `[A-Z]+` | Request.php L1225-1250; FrameworkBundle Configuration.php L87-91, L102-105 |
| Symfony 7.4 (v7.4.23) | yes | header override on for POST unless `allowed_http_method_override: []`; `_method` parameter **off** (`defaultFalse`) | header, else `_method` from body or query | yes | POST | any; GET/HEAD/CONNECT/TRACE deprecated | Request.php L1271, L1275-1278, L1287-1291; Configuration.php L93-103 |
| Symfony 8.0 (v8.0.16) | yes | as 7.4 | as 7.4 | yes | POST | any except GET/HEAD/CONNECT/TRACE (ignored) | Request.php L1210, L1214-1217, L1226-1231; Configuration.php L93-103 |
| Jersey 4.0.3 (JAX-RS) | yes, `HttpMethodOverrideFilter` | OFF (register the filter) | header **and/or the `_method` QUERY param**, both by default, 400 if they disagree | **yes** | POST | any, including GET (form params are moved to the query) | L48-61, L89-100, L132-135, L236-262 |
| Hono v4.13.20 | yes, built-in middleware | OFF | `_method` form field by default; a configured header or **query** param | if configured | **any method except GET** | any | index.ts L33, L71, L76-89, L126-128, L142-144 |

Documentation sources (all fetched 2026-11-23; `e2/out/doc_checks.csv`):
- Spring HiddenHttpMethodFilter javadoc
- Spring Boot 2.2 release notes (GitHub wiki)
- Spring Boot application-properties appendix
- Microsoft Learn: `UseHttpMethodOverride` and `HttpMethodOverrideOptions.FormFieldName`
- expressjs.com method-override
- Rails Guides: Rails on Rack, API-only apps and form helpers
- laravel.com/docs/routing (form method spoofing)
- Symfony framework configuration reference
- pkg.go.dev: gorilla/handlers, chi middleware and net/http
- Starlette middleware
- Django middleware reference
- Hono method-override
- Jersey HttpMethodOverrideFilter javadoc

### Findings

1. **Two of the eight target frameworks have method override reachable in their default configuration.**
   - **Rails**, unless it is an API-only app.
   - **Laravel**, always. Its header override does not even depend on `_method` being enabled, because Symfony's `getMethod` reads `X-HTTP-METHOD-OVERRIDE` for every POST (Symfony 6.4 L1237, 7.4 L1275, 8.0 L1214).
2. **Override is opt-in in three of the eight:** Spring Boot (off since 2.2), ASP.NET Core and Express (an extra package).
3. **Override is absent in the other three:** FastAPI/Starlette, Django and Go (net/http and chi). The only Go method transition is HEAD→GET routing, which is read-only.
4. **Every built-in mechanism only rewrites POST** (Hono is the exception: any method except GET). So the G1/G2 transition is always **a proof for POST executing PUT, PATCH or DELETE**, and in several frameworks also GET.
5. **Query-string override**, the most dangerous variant for DPoP because `htu` excludes the query, is reachable in these:
   - Spring MVC (`getParameter`)
   - Express with the common `methodOverride('_method')` (52.9% of the two common call forms; see §3)
   - gorilla/handlers (`FormValue`)
   - Laravel and Symfony (`$this->query->get('_method')`)
   - Jersey (`_method` query by default)
   - Hono (when configured)

   In all of these, an attacker who holds a proof for `POST /x` only needs to append `?_method=DELETE`. Our bytes stay inside the part of the URI the proof does not cover. Rack, by contrast, reads only the body.
6. **ASP.NET Core accepts any override value**, with no allowlist (L49-52). Express accepts any known method, including GET. Rack accepts GET, HEAD and OPTIONS among others.

## 3. How often projects enable it (GitHub code search)

**Method.**
- **Search API.** We used the authenticated `gh api -X GET search/code -f q=<query>` (`gh` logged in as the user's account, legacy REST code-search engine). This engine searches only default branches and files under 384 KB, skips most forks, and returns `total_count` as an estimate.
- **Rate limit.** We slept 7 s between requests and retried after 61 s on 403/rate-limit errors. No query errored.
- **Runs.**
  - Run 2: 32 queries, 2026-11-22T18:58:13Z to 19:06:16Z.
  - Run 3: 9 file-scoped queries and denominators, 2026-11-22T19:08:14Z to 19:10:14Z.
  - npm downloads for 2026-10-23 to 2026-11-21, from `api.npmjs.org`.
- **Query wording.** Each query's exact text is in the CSVs.
- **Exact-match check.** The legacy engine tokenises quoted phrases. Run 1's raw counts (kept in `e2/out/code_search_raw_run1_counts_only.jsonl`) included absurd totals such as 549,888 for Laravel `@method('DELETE')`. So for every query, runs 2 and 3 fetched the 10 first-page hits and checked case-sensitively that the exact literal appears in the file (`first_page_exact`). Spring's `=true` query had 10/10 exact matches, yet those hits were Spring Boot **1.5** documentation that lists the old default, not configurations. That is why run 3 restricts the Spring query to `filename:application.properties`.

**T1 Selected counts (files, not repositories)**

| framework | measure | query | total_count | first-page exact |
|---|---|---|---|---|
| Spring | enabled in application.properties | `"spring.mvc.hiddenmethod.filter.enabled=true" filename:application.properties` | 7,168 | 10/10 |
| Spring | any hiddenmethod setting in application.properties | `"hiddenmethod.filter.enabled" filename:application.properties` | 7,440 | 10/10 |
| Spring | any hiddenmethod setting in application.yml | `"hiddenmethod" filename:application.yml` | 1,590 | 10/10 |
| Spring | explicit `new HiddenHttpMethodFilter` (Java) | | 2,872 | 10/10 |
| ASP.NET Core | `UseHttpMethodOverride` (C#) | | 225 | 10/10 |
| Express | `"method-override" filename:package.json` | | 69,760 | 10/10 |
| Express | `app.use(methodOverride` (JS) | | 53,824 | 10/10 |
| Express | `methodOverride('_method')` (query getter) | | 22,880 | 10/10 |
| Express | `methodOverride()` (header getter) | | 20,384 | 10/10 |
| gorilla | `HTTPMethodOverrideHandler` (Go) | | 98 | 10/10 |
| Rails | `"config.api_only = true" filename:application.rb` | | 26,240 | 10/10 |
| Rails | `"Rails::Application" filename:application.rb` | | 188,416 | 10/10 |
| Rails | `"use Rack::MethodOverride"` (re-added) | | 2,592 | 10/10 |
| Symfony | `"http_method_override: true" extension:yaml` | | 3,128 | 10/10 |
| Symfony | `"http_method_override: false" extension:yaml` | | 5,392 | 10/10 |
| Symfony | `allowed_http_method_override` (7.4+ restriction) | | 10 | 10/10 |
| Django | `MethodOverrideMiddleware` (third-party) | | 344 | 10/10 |
| Hono | `"hono/method-override"` | | 226 | 10/10 |
| Jersey | `HttpMethodOverrideFilter` (Java) | | 112 | 9/10 |
| Laravel | `"laravel/framework" filename:composer.json` | | 448,512 | 10/10 |
| npm | method-override, monthly downloads | | 9,415,448 | |
| npm | express, monthly downloads | | 845,699,176 | |

**T2 Rough enablement ratios (`e2/summarize_e2.py` → `e2/out/E2_enablement.csv`)**

| framework | ratio | value |
|---|---|---|
| Spring | application.properties setting the override `=true` / application.properties with `spring.application.name` | 7,168 / 721,920 = **0.99%** |
| Spring | share of application.properties hiddenmethod settings that are `=true` | 7,168 / 7,440 = 96.3% |
| ASP.NET Core | files calling `UseHttpMethodOverride` / files calling `UseRouting` | 225 / 383,488 = **0.06%** |
| Express | package.json depending on method-override / package.json mentioning express | 69,760 / 3,727,360 = **1.87%** |
| Express | `app.use(methodOverride` / express package.json | 53,824 / 3,727,360 = 1.44% |
| Express | npm downloads, method-override / express | 9,415,448 / 845,699,176 = **1.11%** |
| Express | query getter `'_method'` among the two common call forms | 22,880 / 43,264 = 52.9% |
| gorilla | `HTTPMethodOverrideHandler` / files importing gorilla/handlers | 98 / 8,496 = 1.15% |
| Rails | api_only apps (override **removed**) / all Rails `application.rb` | 26,240 / 188,416 = 13.9%, so **≈86% keep `Rack::MethodOverride` on** |
| Symfony | yaml `http_method_override: true` / (true + false) | 3,128 / 8,520 = 36.7% |
| Laravel | override on by framework design | all 448,512 Laravel `composer.json` files (structural, not measured) |

**Reading.** Where override is opt-in, roughly **1–2% of projects** turn it on (Spring, Express, gorilla). ASP.NET Core is an order of magnitude lower. Where it is on by default, it stays on: about 86% of Rails apps, and every Laravel app by construction. Express projects that do use method-override pick the query-string getter about half the time, and that getter is exactly the variant DPoP cannot see.

## 4. Implications for the harness (contract §3 `OVERRIDE=on`)

These are the de-facto standard mechanisms the W4/W5 executors should use, chosen to match the table above:
- **Spring:** `spring.mvc.hiddenmethod.filter.enabled=true`, which brings `_method` in the query or form.
- **ASP.NET Core:** `UseHttpMethodOverride()` for the header. The form-field variant disables the header.
- **Express:** `method-override`. Header and query need two `app.use` calls.
- **Rails:** default on.
- **Laravel:** always on.
- **FastAPI, Django, chi:** no built-in exists. With `OVERRIDE=on` they should either record "not supported" or use a third-party package, and the README must say which.

## 5. Limitations

- **Code-search counts are rough indicators, not prevalence estimates.**
  - `total_count` is an engine estimate over files, not repositories, and it includes tutorials, forks with more stars than their parent, vendored copies and documentation.
  - The first-page exact-match rate measures literal presence on the top-ranked hits only. It is biased upward, and the Spring `=true` docs case shows exact matches can still be non-configurations.
  - Numerators and denominators come from different queries, so the ratios are not proportions of one population.
  - We report them as ratios of estimates to show orders of magnitude.
- **The legacy REST engine differs from the newer github.com code search** (which has no public count API). Counts drift over time, so every row carries its UTC timestamp.
- **Enablement ≠ exploitability.** An app that enables override is only affected if a proof-bound POST route shares a path with a PUT, PATCH or DELETE route that has a different effect, and if the verifier sits in front of the override. E3 tests exactly this in the harness.
- **Negative results are scoped to the core frameworks.** FastAPI, Django and chi have no built-in override, but third-party middleware exists (e.g. 344 Python files mention `MethodOverrideMiddleware`). We did not survey every plugin ecosystem.
- **Line numbers refer to the pinned tags.** Newer releases may move them. `e2/pins.tsv` together with `e2/verify_pins.sh` re-establishes them.

## 6. Reproduce

```sh
cd binding/prevalence
sh e2/verify_pins.sh <empty-dir>             # re-fetch pinned sources, byte-compare with data/e2_sources
sh e2/fetch_trees.sh && sh e2/grep_trees.sh  # negative-result greps (FastAPI, Starlette, Django, chi)
.venv/bin/python -I e2/check_docs.py         # documentation phrase checks
gh auth status && .venv/bin/python -I e2/code_search.py          # run 2 (~8 min, rate limited)
.venv/bin/python -I e2/code_search.py --run3                      # run 3
.venv/bin/python -I e2/summarize_e2.py       # ratios
```

The `data/e2_sources/` copies were downloaded by the earlier, interrupted session of this worker. `e2/pins.tsv` records the repo, tag and path for each file, and `verify_pins.sh` proves the copies are byte-identical to those tags.
