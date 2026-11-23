# bh-exec-django: bench API on Django + gunicorn (W4)

What it is: the CONTRACT §3 bench API (`../bench-api.openapi.yaml`) as a Django project
(`benchsite/`) served by gunicorn over WSGI. Image `bh-exec-django:latest`, listening on :8080.

## Versions (pinned, verified inside the image)
- Base image `python:3.12.16-slim-trixie` (Python 3.12.16)
- `Django==6.1.3`, `gunicorn==27.0.1` (`--workers 2 --threads 4`, gthread worker, no access log), and `django-method-override==1.0.4`

## Build / run / test
```sh
docker build -t bh-exec-django:latest .
docker run --rm -p 127.0.0.1:18080:8080 -v $PWD/logs:/logs bh-exec-django:latest
python3 ../conformance/run_conformance.py http://127.0.0.1:18080 --framework django --log-file logs/executor.jsonl
```
Env: `OVERRIDE`, `VERIFY_MODE`, `FRAMEWORK_TAG` (default `django`), `VERIFIER_URL`, `LOG_PATH`.
Results: `../conformance/results_A.md`.

## Structure
- `settings.py` is API-only: `DEBUG=False`, `ALLOWED_HOSTS=["*"]` (gateways may rewrite Host), no database.
  - `MIDDLEWARE = [BenchLogMiddleware, SecurityMiddleware, CommonMiddleware]`, plus `MethodOverrideMiddleware` when `OVERRIDE=on`.
  - Session, auth, messages, CSRF and clickjacking middleware are omitted, because this is a cookie-less, token-authenticated API with no database. `CommonMiddleware` is kept because it implements `APPEND_SLASH` (default `True`).
- `urls.py` uses `path()` with `<str:...>` converters. `/api/v2/` is a prefix mount: `path("api/v2/", include("benchsite.v2urls"))`.
- `views.py` uses class-based `View`s. `http_method_not_allowed` is overridden to return 404 NOT_FOUND, and `handler404` returns JSON NOT_FOUND.
- `middleware.BenchLogMiddleware` is the outermost middleware. It reads `request.method` before any `process_view` hook runs, so it sees the raw method. It takes `raw_target` from gunicorn's `RAW_URI` and `query` from `QUERY_STRING`.

## Method override (`OVERRIDE=on`)
Django has **no built-in method override**. Its forms only support GET and POST, and the docs have
no override setting. The closest widely used package is **`django-method-override` 1.0.4**
(https://gitlab.com/localmed/django-method-override, PyPI `django-method-override`, last release
2020-01-06). It is installed as its README instructs: `method_override` goes in `INSTALLED_APPS`, and
`method_override.middleware.MethodOverrideMiddleware` goes in `MIDDLEWARE`. Its README asks for it to
go after `CsrfViewMiddleware`, which is not installed here. Its semantics, read from the 1.0.4 source:
- It acts in **`process_view`**, i.e. after URL resolution and before the view. Django's URL resolution ignores the method, and the method dispatch happens in `View.dispatch`, so the override fully determines which handler runs.
- Only `POST` requests are considered.
- The sources are `request.POST['_method']` (form body only, **not the query string**), then the `X-HTTP-Method-Override` header. The value is upper-cased.
- Allowed targets (`METHOD_OVERRIDE_ALLOWED_HTTP_METHODS`, default): GET, HEAD, PUT, POST, DELETE, OPTIONS, PATCH. The package also copies the form data to `request.PUT` and similar attributes.

Measured: the header gives deleteAccount, a form body `_method` gives deleteAccount, `?_method`
gives NOT_FOUND, and the header on a GET is ignored.

## Router semantics relevant to path normalisation
Measured (`results_A.md`).
- **Django resolves the percent-decoded `PATH_INFO`.** Under PEP 3333 the WSGI server supplies a decoded `PATH_INFO`, and Django resolves `request.path_info` (https://docs.djangoproject.com/en/6.1/ref/request-response/#django.http.HttpRequest.path_info). Consequences:
  - `%6D` decodes to `m`, so `/api/v1/%6De` routes to `me`.
  - `%2F` becomes `/` before resolution, so `<str:id>` (which matches `[^/]+`) does not match and the request gets 404.
  - `caf%C3%A9` reaches the view as `café`.
- **Trailing slash:** `APPEND_SLASH` only *appends* a slash, with a 301, when the slash-less path fails to resolve and the slashed one resolves (https://docs.djangoproject.com/en/6.1/ref/settings/#append-slash). The bench routes have no trailing slash, so this never fires. `/api/v1/accounts/` gets 404, and nothing removes slashes.
- `//` is not merged, and dot segments are not removed: both give 404. Matching is case-sensitive.
- `;params` are not special. They become part of `<str:>` values, and a static segment gives 404.
- An absolute-form target is accepted: gunicorn parses the absolute URI into `PATH_INFO`, so the request routes to `me`.
- **HEAD becomes GET automatically.** `View.setup` aliases `head` to `get` (https://docs.djangoproject.com/en/6.1/ref/class-based-views/base/#django.views.generic.base.View). It is logged as op `me` with effective method HEAD.
- **OPTIONS** is answered by Django's built-in `View.options`: 200 with an `Allow` header and no bench op. It is logged as `op_id: NOT_FOUND` with status 200 (CONTRACT interpretation 2).
- **gunicorn layer:**
  - It rejects a lower-case method with 400 **before Django runs, so no log line is written**.
  - It **drops headers containing `_`** by default (`header_map = "drop"`, https://docs.gunicorn.org/en/stable/settings.html#header-map). For example, `X_Forwarded_For` never reaches the app. This matters for G3 header smuggling.
  - It joins duplicate headers with `","` (no space). For example, two `X-Forwarded-For` lines give `5.6.7.8,9.9.9.9`. This was measured.
  - It exposes the raw request-target as `RAW_URI`.
- Query: `QueryDict.get("op")` returns the **last** value for a repeated key (measured).

## Known limitations
- Trust-header names come from WSGI `HTTP_*` keys, lower-cased with `_` turned into `-`. That mapping is lossy, but gunicorn's drop rule removes the ambiguous cases.
- See `../conformance/README.md`, "Contract interpretations", for the shared interpretations.
