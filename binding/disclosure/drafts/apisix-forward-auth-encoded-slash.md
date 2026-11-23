# DRAFT — NOT SENT. Private disclosure report (candidate)

**Status:** DRAFT. Do not send. One in-code verification step (see §7) must be
completed before this is suitable to share with the vendor.

**Vendor / component:** Apache APISIX — `forward-auth` plugin
**Our internal id:** RC-W13-A (binding/experiments/ext-gw)
**Classification:** NEW (no prior CVE or advisory found for this specific
view/execution split in `forward-auth`); the adjacent "raw `request_uri` used
by a plugin" class is already public as CVE-2021-43557.

---

## 1. Summary

When APISIX is deployed as an edge gateway using the built-in `forward-auth`
plugin to delegate authorization to an external service, the URI that
`forward-auth` reports to the authorization service (`X-Forwarded-Uri`) and the
request target that APISIX proxies to the upstream can be **different
representations of the same request** when the client sends a percent-encoded
slash (`%2f`).

In our measurements, for a request to
`DELETE /api/v1/accounts/%2facc-alice-1`:

- the external authorizer received `X-Forwarded-Uri:
  /api/v1/accounts/acc-alice-1` — percent-decoded and with the resulting
  duplicate slash merged, i.e. the **normalized** path; and
- the upstream received the **raw** target `/api/v1/accounts/%2facc-alice-1`.

An authorizer that makes an allow/deny decision on the path it is given (here, a
DPoP proof-of-possession check whose bound view is `(DELETE,
/api/v1/accounts/acc-alice-1)`) therefore authorizes one resource while the
upstream executes an operation against a **different** resource identifier
(`%2facc-alice-1`, which many routers decode to `/acc-alice-1`).

## 2. Affected version(s) / configuration

- **Image tested:** `apache/apisix:3.21.0-debian`.
- **Plugin source:** `apisix/plugins/forward-auth.lua`. The line that builds the
  header — `["X-Forwarded-Uri"] = ctx.var.request_uri` — is unchanged from the
  plugin's original 2022 commit (`8dbdd1f…`, PR #6037) through the current `master`
  (confirmed on the `3.21.0` tag and on `master` blame, line ~254, 2026-11-23).
  **No later release changes this line**, so this is not fixed-in-a-later-version.
- **Config:** route `uri=/api/*`, `forward-auth` with `uri=<authorizer>`,
  upstream `pass_host=pass`. Observed identically on our `default-edge` and
  `recommended-edge` profiles (byte-identical) and with method-override off and on.
- **Upstreams affected:** executors whose router keeps `%2f` literal in the path
  parameter — ASP.NET Core / Kestrel, Express, go-chi, Rails (4/8 in our bench).
  FastAPI/Starlette, Django, Spring, Laravel decode or reject `%2f` and return
  404, so they are not affected in this bench.

## 3. Impact (framed carefully)

This is **not** a vulnerability in APISIX on its own, and it is **not** a remote
unauthenticated bypass of APISIX routing. It matters only in a specific,
common deployment: a **path-sensitive external authorization policy** placed in
front of APISIX via `forward-auth`, where the policy's decision depends on the
exact resource path. When that holds, a caller who is authorized for resource A
(and holds a valid credential/proof bound to A's path) can cause the upstream to
act on resource B by appending/altering the last path segment with `%2f`,
because the authorizer sees the normalized A-path and allows, while the upstream
executes on the raw path. In our harness this yields owner-crossing resource
substitution (binding resolution ≥ 2). Severity depends entirely on the
policy; with no path-based policy there is no impact.

## 4. Minimal reproduction

Minimal request (ddmin-minimized, irreducible at 3 units; 96 hits across
frameworks/profiles; 3/3 determinism reruns):

```
DELETE /api/v1/accounts/%2facc-alice-1 HTTP/1.1
Host: api.bench.test
Authorization: DPoP <access-token>
DPoP: <proof: htm=DELETE, htu=http://api.bench.test/api/v1/accounts/acc-alice-1>
Accept: application/json

```

Observed: authorizer view `/api/v1/accounts/acc-alice-1` → allow (sub=alice);
executor `raw_target=/api/v1/accounts/%2facc-alice-1`,
`path_params.id="%2facc-alice-1"`, `op_id=deleteAccount`, HTTP 200.

Local repro (from `binding/harness`, one topology at a time):

```sh
bash ../experiments/ext-gw/scripts/run_one.sh w13-apisix-default-edge-aspnet-ovoff
```

Evidence: `binding/experiments/ext-gw/ddmin/w13-apisix-default-edge-aspnet-ovoff__deleteAccount_g2-pct2f-before-last_alice_bf8b98fbd922.json`;
`runs/w13-apisix-*-edge-{aspnet,express,go-chi,rails}-ov*/hits.jsonl` (signature
`g2-pct2f-before-last`); verifier log shows the decoded view + `allow`.

## 5. Contrast that isolates the plugin behavior

Kong, configured analogously (`pre-function` sending
`X-Original-URI = ngx.var.request_uri`, the **raw** target), does **not** exhibit
this: its authorizer receives the `%2f` form too and denies (`htu_mismatch`).
The difference is which representation reaches the authorizer.

## 6. Suggested fix / mitigation

- **For the plugin:** document explicitly which representation `X-Forwarded-Uri`
  carries, and ensure the authorizer view and the upstream-proxied target are the
  **same** representation (either both raw or both normalized). Offer a config
  switch so `forward-auth` can forward the raw request target.
- **For operators today:** reject or normalize `%2f` at the edge before
  authorization (e.g. decode/normalize and merge slashes consistently for both
  the auth subrequest and the upstream), or make the policy robust to encoded
  separators.

## 7. OPEN VERIFICATION ITEM (must resolve before sending)

The plugin source builds `X-Forwarded-Uri` from `ctx.var.request_uri`, which
resolves via `resty.ngxvar.fetch("request_uri")` (APISIX `core/ctx.lua` has no
special case for `request_uri`). nginx's `$request_uri` is normally the **raw**
target — which would contradict our measurement that the authorizer received the
**decoded/normalized** path. Our end-to-end measurement (verifier log, decoded
view + allow; executor log, raw `%2f`) is solid and reproduced, but the exact
internal reason for the decoding is **not yet pinned**: it could be
`resty.ngxvar.fetch`'s behavior for `request_uri`, an interaction with APISIX's
request handling, or an image-specific detail. Before any disclosure, log the
exact bytes of `X-Forwarded-Uri` as sent by `apache/apisix:3.21.0-debian`, and
the value of `ngx.var.request_uri` vs `ngx.var.uri`, to attribute the mechanism
correctly. Do not state "$uri vs $request_uri" as the cause to the vendor until
this is confirmed.

## 8. References

- APISIX `forward-auth` plugin source: https://github.com/apache/apisix/blob/3.21.0/apisix/plugins/forward-auth.lua
- APISIX `core/ctx.lua`: https://github.com/apache/apisix/blob/3.21.0/apisix/core/ctx.lua
- APISIX `forward-auth` docs: https://apisix.apache.org/docs/apisix/plugins/forward-auth/
- Prior, adjacent class — CVE-2021-43557 (raw `request_uri` used by `uri-blocker`
  enables path-traversal bypass):
  https://apisix.apache.org/blog/2021/11/23/cve-2021-43557-research-report/
- Apache APISIX security page: https://security.apache.org/projects/apisix/
