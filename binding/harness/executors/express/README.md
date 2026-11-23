# bh-exec-express: bench API on Express 4 (W4)

What it is: the CONTRACT §3 bench API (`../bench-api.openapi.yaml`) on Express. Image
`bh-exec-express:latest`, listening on :8080.

## Versions (pinned via `package-lock.json`, verified inside the image)
- Base image `node:24.22.3-alpine3.24` (Node v24.22.3, llhttp parser)
- `express@4.22.3` (path-to-regexp 0.1.13, qs 6.16.2) and `method-override@3.0.0`
- Why Express 4 and not 5.3.0: on 2026-11-23, npm `latest` points to 5.x, but 4.x is still the line most deployed services run. Express 5 changes the router (path-to-regexp v8) and the query parser default (`simple`), so a 5.x executor would be a separate data point. This is noted as a possible extension.

## Build / run / test
```sh
docker build -t bh-exec-express:latest .
docker run --rm -p 127.0.0.1:18080:8080 -v $PWD/logs:/logs -e OVERRIDE=on bh-exec-express:latest
python3 ../conformance/run_conformance.py http://127.0.0.1:18080 --framework express --log-file logs/executor.jsonl --override on
```
Env: `OVERRIDE`, `VERIFY_MODE`, `FRAMEWORK_TAG` (default `express`), `VERIFIER_URL`, `LOG_PATH`, `PORT` (default 8080).
Results: `../conformance/results_A.md`.

## Structure (`app.js`)
The logging middleware runs first. It records `req.url` (the raw request-target) and `req.method`, captures trust headers from `req.rawHeaders` (duplicates joined with `", "` in order), and writes the log on `res` `finish`. Next come `express.json()` and `express.urlencoded()`. Malformed JSON is treated as "no body" so that it reaches graphql dispatch, which then returns `graphql.unknown`. Then method-override (only when `OVERRIDE=on`), then the routes. `/api/v2` is an `express.Router()` mounted with `app.use('/api/v2', v2)`. A final catch-all returns 404 NOT_FOUND, which covers both unknown paths and wrong methods.

## Method override (`OVERRIDE=on`)
This is Express's de-facto standard middleware, **`method-override` 3.0.0**
(https://expressjs.com/en/resources/middleware/method-override.html, source
https://github.com/expressjs/method-override/blob/3.0.0/index.js). Three documented usages are
stacked in this order:
1. `methodOverride('X-HTTP-Method-Override')` is the header getter. Per the README, a getter string starting with `X-` reads a header, and only the first comma-separated value is used.
2. `methodOverride('_method')` is the query getter. Any other getter string is read from the query string (`createQueryGetter` in `index.js`).
3. The README's "custom logic" example reads `req.body._method` from an urlencoded body, after `express.urlencoded()`. This is copied verbatim from the package README.

The defaults are kept: `options.methods = ['POST']`, so only POST requests are examined. The target
must be a method Node knows (`methods` package), and it is upper-cased. When several sources are
present, the later middleware wins. Measured results: header, query and body each turn a POST into
deleteAccount, and the header on a GET is ignored.

## Router semantics relevant to path normalisation
These are measured (`results_A.md`). Sources: the Express 4 API "app settings" table
(https://expressjs.com/en/4x/api.html#app.settings.table) and `lib/router/layer.js`.
- **Case-insensitive routing by default** (`case sensitive routing` is disabled), so `/API/V1/ME` routes to `me`.
- **Non-strict trailing slash by default** (`strict routing` is disabled), so `/api/v1/accounts/` routes to listAccounts and `/api/v1/accounts/acc-alice-1/` routes to getAccount. Express does not redirect.
- **Routing uses the raw (still-encoded) pathname, but parameters are decoded afterwards** with `decodeURIComponent` (`decode_param` in `layer.js`). Consequences:
  - `%2F` does not split a segment but is decoded into the value: `acc-alice-1%2Fx` gives id=`acc-alice-1/x`, and `public/a%2F..%2Fb` gives file=`a/../b`.
  - A percent-encoded static character (`/api/v1/%6De`) does **not** match the static route `/api/v1/me`.
- **Prefix mount leniency:** a `use()` layer matches its prefix with an optional trailing slash, and the router strips it. So `/api/v2//accounts/acc-alice-1` still reaches getAccountV2, and so does a trailing slash.
- `//` and dot segments are not normalised for app-level routes: they get 404.
- `;params` are not special. They become part of a parameter value, and on a static segment they give 404.
- An absolute-form target is accepted: `parseurl` extracts the pathname, so `GET http://api.bench.test/api/v1/me` routes to `me`.
- **HEAD is routed to GET handlers** when no HEAD route exists (`Route._handles_method`). It is logged as op `me` with effective method HEAD.
- OPTIONS: Express's automatic OPTIONS response is pre-empted by the app-level catch-all, so OPTIONS gets 404 NOT_FOUND.
- Node's llhttp rejects a lower-case method (`get`) with **400 before Express runs, so no log line is written** (CONTRACT interpretation 3).
- Query: the `query parser` setting is `extended` (qs) in Express 4. A repeated key such as `?op=freeze&op=close` becomes an **array**, as does `op[]=close`, so both give `accountAction.unknown`.

## Known limitations
- `trust proxy` is off (the default), so `X-Forwarded-*` headers are only logged and never interpreted.
- See `../conformance/README.md`, "Contract interpretations", for the shared interpretations.
