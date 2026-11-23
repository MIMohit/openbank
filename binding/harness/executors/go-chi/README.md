# bh-exec-go-chi: bench API on go-chi v5 / net/http (W4)

What it is: the CONTRACT §3 bench API (`../bench-api.openapi.yaml`) on chi. Image
`bh-exec-go-chi:latest`, listening on :8080.

## Versions (pinned)
- Build image `golang:1.27.4-alpine3.24`, static binary (`CGO_ENABLED=0`). Runtime image `alpine:3.24`.
- `github.com/go-chi/chi/v5 v5.5.0` and `github.com/gorilla/handlers v1.5.2` (indirect dependency `felixge/httpsnoop v1.0.3`), from `go.mod` / `go.sum`.
- The `chi.Mux` is handed **directly** to `http.Server`. `net/http.ServeMux` is not used, so its path cleaning and redirects do not apply.

## Build / run / test
```sh
docker build -t bh-exec-go-chi:latest .
docker run --rm -p 127.0.0.1:18080:8080 -v $PWD/logs:/logs bh-exec-go-chi:latest
python3 ../conformance/run_conformance.py http://127.0.0.1:18080 --framework go-chi --log-file logs/executor.jsonl
```
Env: `OVERRIDE`, `VERIFY_MODE`, `FRAMEWORK_TAG` (default `go-chi`), `VERIFIER_URL`, `LOG_PATH`, `PORT`.
Results: `../conformance/results_A.md`.

## Structure (`main.go`)
`logMW(handlers.HTTPMethodOverrideHandler(chiRouter))`. The override wrapper is present only when
`OVERRIDE=on`. `logMW` records `r.Method` and `r.RequestURI` (the raw request-target) up front. The
override handler mutates the *same* `*http.Request`, so the effective method is read after it runs.
`/api/v2` is a separate `chi.NewRouter()` attached with `r.Mount("/api/v2", v2)`. `NotFound` and
`MethodNotAllowed` both return 404 NOT_FOUND on both routers.

## Method override (`OVERRIDE=on`)
chi has **no method-override middleware**. Its `middleware` package
(https://pkg.go.dev/github.com/go-chi/chi/v5/middleware) has none. The widely used `net/http`-compatible
mechanism is **gorilla/handlers `HTTPMethodOverrideHandler`**
(https://pkg.go.dev/github.com/gorilla/handlers#HTTPMethodOverrideHandler, source `handlers.go`
in v1.5.2). It wraps any `http.Handler`, including a chi router. Its semantics, read from source:
- Only `POST` requests are considered.
- `r.FormValue("_method")` is read first. `FormValue` merges the **query string and an urlencoded body**, so `?_method=DELETE` works as well as a form field. The `X-HTTP-Method-Override` header is read only if the form value is empty, so the form wins over the header.
- The only accepted targets are exactly `PUT`, `PATCH` and `DELETE`, case-sensitive.

Measured: header, query and body each turn a POST into deleteAccount, and the header on a GET is ignored.

## Router semantics relevant to path normalisation
Measured (`results_A.md`).
- **chi routes on `r.URL.RawPath` when it is set, else on `r.URL.Path`** (`mux.go` `routeHTTP`, v5.5.0 line 462). Go's `net/url` sets `RawPath` only when the received encoding differs from Go's default encoding of the decoded path (https://pkg.go.dev/net/url#URL). Consequences:
  - `%2F` does not split a segment, and the value stays **raw**: `acc-alice-1%2Fx` gives id=`acc-alice-1%2Fx`, and `public/a%2F..%2Fb` gives file=`a%2F..%2Fb`.
  - Any non-default escape switches routing to raw mode: `acc%2Dalice-1` gives id=`acc%2Dalice-1`, so **`URLParam` is not decoded**. A handler comparing the id to `acc-alice-1` would see a different value.
  - Where the default encoding is used, `RawPath` is empty and the value arrives decoded: `caf%C3%A9` gives `café`. Decoding therefore depends on the input.
  - `/api/v1/%6De` does not match the static route `me`, because routing is on the raw path.
- No trailing-slash handling (`middleware.StripSlashes` and `RedirectSlashes` are opt-in and not used), no `//` merging and no dot-segment cleaning (`middleware.CleanPath` is opt-in). All of these get 404. Matching is case-sensitive.
- `;params` are not special. They become part of a parameter, and a static segment gets 404.
- An absolute-form target is accepted by net/http, which parses it into `r.URL`, so the request routes to `me`.
- **HEAD is not automatic** (`middleware.GetHead` is opt-in), so it gets 404. OPTIONS gets 404.
- net/http accepts a lower-case method token (`get`). It reaches chi and gets 404.
- Query: `url.Values.Get("op")` returns the **first** value for a repeated key (measured). Since Go 1.17, `;` is not a query separator.

## Known limitations
- `origin-routed` decodes the chi parameter only when `RawPath` was set, then re-encodes it (CONTRACT interpretation 6), so the canonical URI is consistent with the other executors.
- The Go header map is canonicalised. Trust-header names are lower-cased, and repeated headers are joined with `", "`.
- See `../conformance/README.md`, "Contract interpretations", for the shared interpretations.
