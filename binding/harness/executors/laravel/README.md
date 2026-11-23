# bh-exec-laravel: bench API executor in Laravel (W5)

The CONTRACT §3 bench API in Laravel 12, served by FrankenPHP (Caddy + embedded PHP, classic mode). Image `bh-exec-laravel:latest`, listening on 8080.

## Versions (`/app/VERSIONS.txt` in the image)
| component | version |
|---|---|
| laravel/framework | 12.73.0 (skeleton `laravel/laravel` 12.12.2) |
| symfony/http-foundation, symfony/routing | 7.4.23 |
| PHP | 8.3.37 (ZTS) |
| Server | FrankenPHP 1.14.0 (`dunglas/frankenphp:1.14.0-php8.3-bookworm`), `php_server` directive |
| Composer (build only) | 2.11.2 |

## Build / run / test
```sh
cd binding/harness/executors/laravel && docker build -t bh-exec-laravel:latest .
docker run -d --name w5-laravel -p 127.0.0.1:18080:8080 -e OVERRIDE=on -v $PWD/logs:/logs bh-exec-laravel:latest
cd .. && bash spring/tools/w5_conformance.sh laravel && python3 spring/tools/w5_report.py laravel
```
Env: `OVERRIDE`, `VERIFY_MODE`, `FRAMEWORK_TAG` (default `laravel`), `VERIFIER_URL`, `LOG_FILE`. Results: [CONFORMANCE.md](CONFORMANCE.md) (all 6 configurations pass, with 0 failures).
The shared W5 tools live in `../spring/tools/`.

## Implementation
The build stage runs `composer create-project` for the stock skeleton and copies `overlay/` on top of it:
- `bootstrap/app.php` uses `withRouting(using: …)` to load only `routes/bench.php`, with no `web` group and therefore no sessions or CSRF. `BenchLog` is prepended as the outermost global middleware. It maps an unmatched 404/405 (`NotFoundHttpException`/`MethodNotAllowedHttpException`, rendered by the handler) to 404 `NOT_FOUND` and writes the log line.
- `routes/bench.php` uses `Route::prefix('api/v1')->group(...)`. **`/api/v2` mount:** `Route::prefix('api/v2')->group(...)`, a Laravel route group with a prefix.
- G1 query dispatch uses the idiomatic `$request->input('op')`. Laravel's input merges the query and the body (form or JSON), with **body over query**. Body dispatch uses `json_decode($request->getContent())` whatever the Content-Type.
- `raw_method` is `$_SERVER['REQUEST_METHOD']`, the exact token. (`getRealMethod()` would upper-case it.) `raw_target` is FrankenPHP's `REQUEST_URI`.
- VERIFY_MODE: the verifier is called in the controller, with Laravel's `Http` client (Guzzle), a 3 s connect and 5 s total timeout, failing closed.

## Method override (`OVERRIDE`)
**Mechanism:** Laravel's built-in "form method spoofing" (https://laravel.com/docs/12.x/routing#form-method-spoofing), implemented by Symfony HttpFoundation's `Request::getMethod()`.
- In stock Laravel it is **always on and has no config switch**:
  - `Illuminate\Http\Request::capture()` (line 80) and `Illuminate\Foundation\Http\Kernel::handle()` (line 142) both call `enableHttpMethodParameterOverride()`.
  - Symfony's `getMethod()` honours `X-HTTP-Method-Override` on POST unconditionally, and then `_method` from `$this->request` (the body; Laravel sets the JSON bag for JSON requests) **or `$this->query`**.
  - Source: `vendor/symfony/http-foundation/Request.php` `getMethod()` in the image, v7.4.23.
- `OVERRIDE=on` is the stock behaviour, untouched.
- `OVERRIDE=off` uses Symfony's own API, `Request::setAllowedHttpMethodOverride([])` (new in http-foundation 7.4, and documented as framework option `allowed_http_method_override`, https://symfony.com/doc/current/reference/configuration/framework.html). It is called in `public/index.php` before `Request::capture()`. With an empty array `getMethod()` returns the real method. (An earlier attempt pinned the method after `capture()`. That failed because `capture()` had already enabled `_method`, and it was replaced.)
- **Both `_method` and `X-HTTP-Method-Override` are supported natively.**
- **Measured** (probes, OVERRIDE=on):
  - Header, form `_method`, **query `?_method=`** and **JSON `{"_method":"DELETE"}`** all override. It is the most permissive of the four W5 executors.
  - The header **wins over** `_method` (form PUT + header DELETE gives DELETE).
  - `GET` is accepted (Symfony 7.4 emits a deprecation; it is ignored in Symfony 8). Values are upper-cased.
  - An override is applied only when the real method is POST.

## Router normalisation semantics
Raw data: `conformance-out/probes_ov*.{md,json}`.

| input | result | note |
|---|---|---|
| `%2F` in `{id}` | **404**. Laravel matches the *decoded* path (`Request::decodedPath()`), and the default `{id}` requirement `[^/]+` then fails | |
| `%61ccounts` | 200 (decoded before matching) | |
| `/../`, `%2e%2e`, `/./` | 404 | |
| `;x=1` | literal segment: 404. In `{id}` it is kept (`acc-alice-1;x=1`) | |
| trailing slash | **matches**. Route URIs and the request path are compared without the trailing `/` | observed |
| `//` | 404 | |
| case | 404 (case-sensitive) | |
| `.json` suffix | kept in `{id}`; `/accounts.json` gives 404 | |
| `\`, `%5C` | 404 | |
| `%00` in `{id}` | accepted (`acc\u0000x`) | |
| `#frag` | 404. FrankenPHP/Caddy keeps the fragment as part of the path and re-encodes it: `REQUEST_URI` (and therefore `raw_target`) is `/api/v1/me%23frag` | so `raw_target` is **not byte-exact** for targets containing `#` |
| absolute-form | routed by path | |
| lower-case method `get` | **200 getAccount**. Symfony upper-cases the method; the log records `raw_method="get"`, `effective_method="GET"` | |
| HEAD | routed to the GET route (Laravel registers HEAD with GET). OPTIONS: 200 from Laravel's automatic OPTIONS response (`op_id` NOT_FOUND) | |
| `?op=freeze&op=close` | **close** (PHP: the last value wins) | |
| `?op[]=close` | unknown (an array) | |
| `op` in the form body or JSON body | **close** | |
| `?op=freeze` + form `op=close` | **close**. `input()` gives the body precedence over the query, **the opposite of Rails** | |
| graphql duplicate `operationName` | deleteProfile (PHP `json_decode`: the last key wins) | |

## Contract interpretations
W4's interpretations #1–#12 are applied. Laravel-specific choices:
- OVERRIDE=off needs one line of framework API, `Request::setAllowedHttpMethodOverride([])`, because Laravel has no setting for it. No custom override logic was added for `on`.
- Laravel's automatic OPTIONS 200 is kept and logged as NOT_FOUND (interpretation #2).
- `raw_target` is FrankenPHP's `REQUEST_URI`. It is byte-exact for every target W4's conformance test sends, but Caddy re-encodes a raw `#` as `%23`. PHP under Caddy exposes no more raw request line than this.

## Known limitations
- No `.env` APP_KEY is used: no sessions, cookies or encryption are needed. The skeleton's `.env` from `create-project` is present but unused for anything security-relevant.
- FrankenPHP worker mode is not used (classic mode), so each request boots the framework. That makes it slower, but it is the simplest and most faithful setup.
