# Gateways (W6)

Config renderers for the six edge gateways of the binding-soundness harness (CONTRACT section 5).
Each gateway listens on `:8000` and routes `/api/` to `executor:8080`, keeping the path. In
`placement=edge|both` it calls the verifier (`verifier:9100`) through the matching CONTRACT
section 4 adapter and passes `Authorization` and `DPoP`. In `placement=origin` the gateway is a
plain proxy, and the orchestrator sets the executor's `VERIFY_MODE=origin-raw`.

```
gateways/
  common.py            pinned images, ports, the strict deny-list regex
  <gw>/render.py       render(profile, placement, outdir) -> compose service fragment
  <gw>/rendered/       all 9 profile-placement renderings, for review (python -m gateways.render_all)
  render_all.py
```

## How to run and test
- `cd binding/harness && python -m gateways.render_all` re-renders `*/rendered/` (stdlib only).
- These checks ran on all rendered configs and passed (2026-11-23):
  - `haproxy -c`: 9/9.
  - `nginx -t` (with `--add-host executor/verifier`): 9/9.
  - `envoy --mode validate`: default, recommended and strict × edge and origin (6/6).
  - `kong config parse`: 4 configs (every `*-edge` plus `strict-origin`).
  - Traefik and APISIX have no offline validator, so their configs were checked by starting them in the smoke test.
- End-to-end: `orchestrator/smoke.py` brings up every gateway × profile at `placement=edge` with
  the W6 stubs. Results are in `../orchestrator/SMOKE.md`.

## Pinned images
Tags are pinned exactly. The digests below are the local RepoDigests after `docker pull` on 2026-11-23 (linux/arm64 host; the digest is the multi-arch index digest).

| gateway | image | digest |
|---|---|---|
| envoy | `envoyproxy/envoy:v1.39.6` | `sha256:1fde8efee875e4e4f6a39a90fe49d9338e1caacce5762034ef9fb4bbb9ad6aed` |
| traefik | `traefik:v3.7.19` | `sha256:a6c0194dda77bcb804824580f36fa7edc56e315b1acfe933366c8b52844a78a4` |
| nginx | `nginx:1.30.7-alpine` (stable branch) | `sha256:caf4e1e032a20f9c3c5e28fc7f25ffd768ad8677b4975c54193075997b3a97e3` |
| kong | `kong:3.9.5` (last OSS image line) | `sha256:e9b87ddd0e6087792586e2cbba5ce91eadcbdd3d3673249aa4606f7207408c0d` |
| apisix | `apache/apisix:3.21.0-debian` | `sha256:1741a8e1186e5c39ea10e6b4fb3e682534d1705efb8328195de5b41ad0657380` |
| haproxy | `haproxy:3.2.27` (3.2 LTS branch) | `sha256:5ddf08c89c95a311f4bfb761d74016597fdca76ecfcdf169ed1bab117f3da1ea` |
| stubs/probe | `python:3.12.16-slim-trixie` | `sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b` |

## What the profiles mean
- **default:** the vendor's defaults, plus only what is needed to route and to call the verifier.
- **recommended:** settings the vendor's own docs advise for security or normalisation. Only Envoy
  publishes a single edge-hardening checklist, and Traefik's docs give explicit guidance on the
  encoded-character options. For NGINX, Kong, APISIX and HAProxy no vendor publishes a
  "recommended normalisation profile", so recommended is the set of documented hardening
  directives that apply to request-target and header handling. Each one is listed below with its doc link.
- **strict:** the strictest normalisation and rejection the gateway offers. For a class of input
  that a gateway has no native toggle for, strict adds a rule in the gateway's own config language
  (nginx `if`/`return`, HAProxy `http-request deny`, a Kong or APISIX serverless pre-function).
  The rule rejects raw paths matching `common.STRICT_DENY_PATH_REGEX`:
  - encoded `/ \ NUL ; % ? # .` (`%2f %5c %00 %3b %25 %3f %23 %2e`);
  - a literal `;` or `\`;
  - raw dot-segments;
  - empty segments `//`.

  It also rejects method tokens outside GET, HEAD, POST, PUT, DELETE, PATCH and OPTIONS.
  This mirrors what Envoy and Traefik strict reject natively. These rules are **harness-defined**, so
  the paper should report them as the "strict normalisation" baseline (plan E8), not as vendor defaults.

## Per-gateway details and citations

### Envoy (`ext_authz`, HTTP service)
- Wiring: the `envoy.filters.http.ext_authz` filter with `http_service.server_uri: http://verifier:9100`,
  `path_prefix: /authz/envoy`, and `allowed_headers` set to `authorization` and `dpop`. Envoy
  also always sends the method, `Host` and path, so the verifier gets `/authz/envoy<original path?query>`.
  Response headers matching `x-verified-*` are copied upstream, and `www-authenticate` goes to the client.
  `failure_mode_allow: false`.
  - https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_authz_filter
  - https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/ext_authz/v3/ext_authz.proto
- default: the HCM's defaults: `normalize_path` false, `merge_slashes` false,
  `path_with_escaped_slashes_action` unset (`IMPLEMENTATION_SPECIFIC_DEFAULT`, which is KEEP_UNCHANGED),
  `headers_with_underscores_action` ALLOW.
- recommended: from the Envoy edge-proxy best practices and the HCM path-normalisation docs:
  - `normalize_path: true`
  - `merge_slashes: true`
  - `path_with_escaped_slashes_action: UNESCAPE_AND_REDIRECT`
  - `headers_with_underscores_action: REJECT_REQUEST`
  - `use_remote_address: true`
  - idle and request-header timeouts

  Sources:
  - https://www.envoyproxy.io/docs/envoy/latest/configuration/best_practices/edge
  - https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/network/http_connection_manager/v3/http_connection_manager.proto
    (fields `normalize_path`, `merge_slashes`, `path_with_escaped_slashes_action`)
- strict: as recommended, except `path_with_escaped_slashes_action: REJECT_REQUEST`, plus `strip_any_host_port: true`.
- Path normalisation runs in the HCM before any filter, so in recommended and strict ext_authz
  and the router both see the normalised path.

### Traefik (ForwardAuth)
- Wiring: the `forwardAuth` middleware with `address: http://verifier:9100/authz/fwd`,
  `authRequestHeaders: [Authorization, DPoP]` and `authResponseHeadersRegex: ^X-Verified-`.
  Traefik sends X-Forwarded-Method, -Proto, -Host, -Uri and -For to the auth server.
  - https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/forwardauth/
- default: the entryPoint defaults: `http.sanitizePath: true`, all `http.encodedCharacters.allow*`
  options true, `aliasHeadersStrategy: keep`, and `forwardedHeaders` not trusted (`insecure: false`, no `trustedIPs`).
  - https://doc.traefik.io/traefik/reference/install-configuration/entrypoints/
- recommended: the docs say turning sanitizePath off "is not safe", and recommend disallowing
  encoded characters when the backend is not fully RFC 3986 compliant, to avoid split views. So
  this profile sets:
  - `sanitizePath: true`, explicitly;
  - `allowEncodedSlash`, `allowEncodedBackSlash`, `allowEncodedNullCharacter` and `allowEncodedSemicolon` false;
  - `trustForwardHeader: false`, explicitly (the docs ask for an explicit value);
  - bounded `maxBodySize` and `maxResponseBodySize` (the docs "strongly recommend" setting them).
- strict: all seven `encodedCharacters.allow*` options false, and `aliasHeadersStrategy: reject`.
- Source: the v3.7 docs, read 2026-11-23. The docs do not say in which version each option was introduced.

### NGINX (`auth_request`)
- Wiring: `auth_request /_bh_authz`, an internal location that does
  `proxy_pass http://verifier:9100/authz/orig` with:
  - `X-Original-URI $request_uri` (the raw target, as in the vendor example);
  - `X-Original-Method $request_method`;
  - `X-Original-Host $host`;
  - `proxy_pass_request_body off`.

  Client headers, including Authorization and DPoP, are passed to the subrequest by default.
  `/api/` uses `proxy_pass http://executor:8080` with no URI part, so the request URI is passed
  unchanged. Note the split: NGINX *matches* the location on the normalised `$uri`, while the
  verifier gets the raw `$request_uri`.
  - https://nginx.org/en/docs/http/ngx_http_auth_request_module.html
  - https://docs.nginx.com/nginx/admin-guide/security-controls/configuring-subrequest-authentication/
  - https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_pass
- default: vendor defaults: `merge_slashes on`, `ignore_invalid_headers on`, `underscores_in_headers off`,
  and `proxy_set_header Host $proxy_host`, so **the executor sees `Host: executor:8080`**.
- recommended: from the core module and proxy module directive docs:
  - `server_tokens off`
  - `merge_slashes on`, `underscores_in_headers off` and `ignore_invalid_headers on`, all explicit
  - `client_max_body_size 1m`
  - `proxy_http_version 1.1`
  - `Host $host`
  - `X-Forwarded-For $remote_addr`, overwriting any client value rather than appending to it
  - `X-Forwarded-Proto $scheme`

  Source: https://nginx.org/en/docs/http/ngx_http_core_module.html
- strict: recommended plus the harness deny rule (`if ($bh_raw_path ~* ...) { return 400; }`) and
  the method allow-list. NGINX has no built-in toggle for rejecting encoded characters.

### Kong OSS 3.9.5 (DB-less; forward-auth through the `pre-function` serverless plugin)
- Kong OSS ships no forward-auth plugin. Third-party plugins exist, but they need a custom image.
  The bundled Serverless Functions plugin (`pre-function`) runs Lua in the access phase. It calls
  `/authz/orig` with lua-resty-http, sending:
  - `X-Original-Method`: `kong.request.get_method()`;
  - `X-Original-URI`: `ngx.var.request_uri` (raw);
  - `X-Original-Host`: `ngx.var.http_host`;
  - `Authorization` and `DPoP`.

  A non-200 answer becomes a 401, and `X-Verified-*` headers are copied upstream.
  - https://developer.konghq.com/plugins/pre-function/ (formerly https://docs.konghq.com/hub/kong-inc/serverless-functions/)
- This needs `KONG_UNTRUSTED_LUA=on`. The 3.x default `untrusted_lua = sandbox` exposes only
  `require` plus the modules listed in `untrusted_lua_sandbox_requires`, and neither `ngx` nor
  `kong`. This was checked in the image's `kong/tools/sandbox.lua`. The setting affects only
  whether the plugin may run, not path handling.
  - https://developer.konghq.com/gateway/configuration/ (`untrusted_lua`)
- Kong's `nginx_kong.lua` template hard-codes `underscores_in_headers on;` in the http block, so Kong's default **accepts underscore headers**. The recommended profile overrides it in the proxy server block (`KONG_NGINX_PROXY_UNDERSCORES_IN_HEADERS=off`), because an http-level override fails with "directive is duplicate". The same goes for `merge_slashes`.
- default: route `strip_path: false` and `preserve_host: false` (the Kong default), so
  **the executor sees `Host: executor:8080`**. Kong's router applies its built-in path normalisation,
  which cannot be configured.
- recommended:
  - route `preserve_host: true`;
  - `headers = off`;
  - `trusted_ips` unset, so client X-Forwarded-* headers are not trusted;
  - injected nginx directives (`KONG_NGINX_HTTP_*`): `underscores_in_headers off`,
    `merge_slashes on` (both in the proxy server block) and `client_max_body_size 1m`.

  Sources:
  - https://developer.konghq.com/gateway/configuration/ (`headers`, `trusted_ips`, injected nginx directives)
  - https://developer.konghq.com/gateway/entities/route/ (`preserve_host`, `strip_path`)
- strict: recommended plus the harness deny rule and method allow-list, as Lua in the same `pre-function`, run before authz.

### Apache APISIX 3.21.0 (standalone, `forward-auth` plugin)
- Wiring: `forward-auth` with `uri: http://verifier:9100/authz/fwd`, `request_method: GET`,
  `request_headers: [Authorization, DPoP]`, `upstream_headers: X-Verified-*` and
  `client_headers: [WWW-Authenticate]`.
  - https://apisix.apache.org/docs/apisix/plugins/forward-auth/
- Behaviour, from reading `apisix/init.lua` and `plugins/forward-auth.lua` in the pinned image:
  - APISIX overwrites `ctx.var.request_uri` with its normalised `uri` before plugins run.
  - forward-auth sends `X-Forwarded-Uri = ctx.var.request_uri`.
  - So the verifier sees APISIX's normalised view. The original stays in `ctx.var.real_request_uri`.
- default: from `apisix/cli/config.lua` in the image:
  - `nginx_config.http.underscores_in_headers: "on"`;
  - `normalize_uri_like_servlet: false`, `delete_uri_tail_slash: false`, `match_uri_encoded_slash: false`.
- recommended: `underscores_in_headers: "off"`, `enable_server_tokens: false` and `client_max_body_size: 1m`.
  - https://github.com/apache/apisix/blob/master/conf/config.yaml.example
  - https://apisix.apache.org/docs/apisix/deployment-modes/#standalone
- strict: recommended plus `normalize_uri_like_servlet: true`. This applies servlet-style `;`
  path-parameter handling before routing, and is the strictest normalisation knob APISIX has. On
  top of that, a `serverless-pre-function` (rewrite phase) with the harness deny rule and method allow-list.
  - https://apisix.apache.org/docs/apisix/plugins/serverless/

### HAProxy 3.2.27 (Lua action using `core.httpclient`)
- Wiring: a Lua `http-req` action `bh_authz` (`bh_authz.lua`) gets `/authz/orig` from the verifier, sending:
  - `X-Original-Method`: `method`;
  - `X-Original-URI`: `url`, the request target as currently held, so after any normalize-uri rules;
  - `X-Original-Host`: `req_fhdr(host)`;
  - Authorization and DPoP via `req_fhdr`, the full header value with no comma splitting.

  A non-200 answer leads to `http-request return status 401`. SPOE would be the other option;
  Lua was chosen because it needs no agent process.
  - https://docs.haproxy.org/3.2/configuration.html (`lua-load`, `http-request lua.<name>`, `http-request return`)
  - https://www.arpalert.org/src/haproxy-lua-api/3.2/index.html (`core.httpclient`, `txn.f`)
- default: no URI normalisation, and header names preserved.
- recommended: `http-request normalize-uri` with these normalisers, placed before the authz action
  so the verifier and the backend see the same URI:
  - `fragment-strip`
  - `path-strip-dotdot`
  - `path-merge-slashes`
  - `percent-decode-unreserved`
  - `percent-to-uppercase`

  It also sets `option http-restrict-req-hdr-names delete`.
  **In HAProxy 3.2 `normalize-uri` is still marked experimental** and needs the global
  `expose-experimental-directives`. That was verified with `haproxy -c`.
  - https://docs.haproxy.org/3.2/configuration.html#4.2-http-request%20normalize-uri
  - https://docs.haproxy.org/3.2/configuration.html#4.2-option%20http-restrict-req-hdr-names
- strict: these rules run in order:
  1. the method allow-list and the harness raw-path deny rule (`http-request deny`), before any normalisation;
  2. the normalisers in their strict variants (`path-strip-dotdot full`, `percent-decode-unreserved strict`, `percent-to-uppercase strict`);
  3. `http-restrict-req-hdr-names reject`.
- `tune.lua.bool-sample-conversion normal` is set to silence the 3.2 ambiguity warning.

## Known limitations
- Hosts differ by default. NGINX's and Kong's default profiles send `Host: executor:8080`
  upstream (vendor default), while the other gateways preserve `api.bench.test`. In origin
  placement that changes the executor's `X-Original-Host`. This is kept on purpose as vendor-default behaviour.
- Everything is HTTP/1.1 cleartext (CONTRACT section 1). HTTP/2-specific normalisation options are not exercised.
- The "recommended" profiles for NGINX, Kong, APISIX and HAProxy are my selection of documented
  directives, not a vendor-published profile (see "What the profiles mean").
- The Kong and HAProxy authz adapters are harness code, about 30 lines of Lua each, written to
  the vendors' documented extension APIs. They are not vendor-supplied plugins.
- All 18 gateway × profile edge configs were run behind both the W6 stub verifier and the real W3 `bh-verifier:latest` (image `sha256:263f3231d20f…`), with the stub executor. See `../orchestrator/SMOKE.md`. No real executor has been run behind them yet.
- The smoke test checks only that a canonical request is allowed and routed. It does not check that the strict deny rules fire. The mutator (W7) exercises those.
