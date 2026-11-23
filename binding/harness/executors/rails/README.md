# bh-exec-rails: bench API executor in Rails (W5)

The CONTRACT §3 bench API as a minimal Rails application (railties + actionpack, no ActiveRecord) on Puma. Image `bh-exec-rails:latest`, listening on 8080.

## Versions (Gemfile.lock in the image)
| component | version |
|---|---|
| Rails (railties, actionpack) | 8.1.4 |
| Rack | 3.2.9 |
| Puma | 8.1.2 (single mode, 4–8 threads) |
| Ruby | 3.3.14 (`ruby:3.3.14-slim-bookworm`) |
| json gem | 3.1.0 |

## Build / run / test
```sh
cd binding/harness/executors/rails && docker build -t bh-exec-rails:latest .
docker run -d --name w5-rails -p 127.0.0.1:18080:8080 -e OVERRIDE=on -v $PWD/logs:/logs bh-exec-rails:latest
cd .. && bash spring/tools/w5_conformance.sh rails && python3 spring/tools/w5_report.py rails
```
Env: `OVERRIDE`, `VERIFY_MODE`, `FRAMEWORK_TAG` (default `rails`), `VERIFIER_URL`, `LOG_FILE`. Results: [CONFORMANCE.md](CONFORMANCE.md) (all 6 configurations pass, with 0 failures).
The shared W5 tools live in `../spring/tools/`.

## Implementation
- `config/application.rb` defines a full (non-`api_only`) `Rails::Application`, so the default middleware stack includes `Rack::MethodOverride`. `BenchLog` is inserted at position 0, the outermost middleware. It captures `REQUEST_METHOD` and Puma's `REQUEST_URI` (the request-target as received), maps an unmatched 404/405 to 404 `NOT_FOUND`, and writes the log line. `config.hosts.clear` accepts `Host: api.bench.test`.
- `config/routes.rb` declares `scope "/api/v1"` routes to `BenchController`. **`/api/v2` mount:** a mountable **Rails engine** (`BenchV2::Engine`, `isolate_namespace`), mounted with `mount BenchV2::Engine => "/api/v2"`. The engine's routes (`lib/bench_v2/config/routes.rb`) are relative, and the engine sees `SCRIPT_NAME=/api/v2`. The engine has its own `config.root` (`lib/bench_v2`), because the default inferred root would be the app root and would load `config/routes.rb` twice. That was the crash in the first build.
- `publicFile` uses `constraints: { file: %r{[^/]+} }`. Rails' default segment regex `[^/.?]+` would otherwise split `.txt` off as `:format`.
- G1 query dispatch uses the idiomatic `params[:op]`. Rails `params` merges the path, query and body (form or JSON) parameters. Body dispatch uses `JSON.parse(request.raw_post)` whatever the Content-Type.
- VERIFY_MODE: the verifier is called in the controller after routing, with `Net::HTTP`, a 3 s open timeout and a 5 s read timeout, failing closed.

## Method override (`OVERRIDE`)
**Mechanism:** `Rack::MethodOverride`, which is in Rails' default middleware stack. The Rails on Rack guide lists it, saying it "allows the method to be overridden if `params[:_method]` is set" (https://guides.rubyonrails.org/rails_on_rack.html). `OVERRIDE=on` keeps the default stack. `OVERRIDE=off` removes it with the documented `config.middleware.delete Rack::MethodOverride`.
- Source in the image, `rack-3.2.9/lib/rack/method_override.rb`:
  - `ALLOWED_METHODS = %w[POST]`.
  - `HTTP_METHODS = %w[GET HEAD PUT POST DELETE OPTIONS PATCH LINK UNLINK]`.
  - It reads `req.POST["_method"]` (form-data / parseable body only), **falling back to** `env["HTTP_X_HTTP_METHOD_OVERRIDE"]`.
  - The value is upper-cased, and the original is kept in `rack.methodoverride.original_method`.
  - https://github.com/rack/rack/blob/main/lib/rack/method_override.rb
- **`X-HTTP-Method-Override` is supported natively** (header) **and so is `_method`** (form body).
- **Measured** (probes, OVERRIDE=on):
  - Header and form both work. `?_method=` in the query is **not** honoured (404), and a JSON `_method` is **not** honoured.
  - `_method=GET` / header `GET` are accepted (POST→GET). Lower-case values are upper-cased.
  - Form `_method=PUT` plus header DELETE gives **PUT**, because the param is checked first.

## Router normalisation semantics (Journey router)
Raw data: `conformance-out/probes_ov*.{md,json}`.

| input | result | source / note |
|---|---|---|
| `%2F` in `{id}` | **matches, and the param is decoded to `acc/alice`** | Journey matches the still-encoded path and unescapes params afterwards |
| `%61ccounts` (literal segment) | 404, because literal segments are matched against the encoded path | |
| `/../`, `%2e%2e`, `/./` | 404 | |
| `;x=1` | literal segment: 404. In `{id}` it is kept (`acc-alice-1;x=1`) | |
| trailing slash | **matches**. `/accounts/` → listAccounts | `ActionDispatch::Journey::Router::Utils.normalize_path` strips trailing `/` |
| `//` (leading or in the middle, also after `/api/v2`) | **matches**: `//api/v1/accounts` → listAccounts, `/api/v1//accounts/x` → getAccount | `normalize_path` does `path.squeeze!("/")` (source in the image: actionpack-8.1.4 `journey/router/utils.rb`) |
| case | 404 (case-sensitive) | |
| `.json` suffix | **stripped as `:format`**. `/accounts/acc-alice-1.json` gives `id=acc-alice-1`, and `/accounts.json` → listAccounts | Rails routing guide: every route gets an optional `(.:format)` |
| `\` | 400 from Puma. `%5C`: 404 | |
| `%00` in `{id}` | accepted (`id="acc\u0000x"`) | |
| `#frag` | Puma drops the fragment, giving 200 me (`raw_target` is the path without `#frag`, as Puma reports it) | |
| absolute-form | routed by path | |
| lower-case method `get` | 400 from Puma; no log line | |
| HEAD | routed to the GET route, giving getAccount (Rails turns HEAD into GET for matching). OPTIONS: 404 | |
| `?op=freeze&op=close` | **close** (the last value wins in Rack's query parser) | |
| `?op[]=close` | unknown (an Array) | |
| `op` in the form body or JSON body | **close**. `params` includes the request body; JSON is parsed by `ActionDispatch::Request` | |
| `?op=freeze` + form `op=close` | **freeze**. In `params` the query values win over body values | |
| graphql duplicate `operationName` | unknown. **json 3.1.0 raises `JSON::ParserError: duplicate key`** (verified in the image), so the input counts as invalid JSON | |

## Contract interpretations
W4's interpretations #1–#12 are applied. Rails-specific choices:
- `raw_target` = Puma's `REQUEST_URI` (fragment removed by Puma).
- The trust-header names come from Rack `HTTP_*` keys with `_`→`-`. This is lossy: `X_Forwarded_For` and `X-Forwarded-For` are indistinguishable, which is the same caveat as WSGI in interpretation #9.
- `path_params` are Rails' decoded values (interpretation #8).

## Known limitations
- No ActiveRecord or session middleware is loaded; only the routing and controller layers are exercised.
- Requests rejected by Puma (lower-case method, `\`) produce no log line (interpretation #3).
