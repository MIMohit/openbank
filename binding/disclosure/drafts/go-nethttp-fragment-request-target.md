# DRAFT — NOT SENT. Private disclosure report (candidate, low priority)

**Status:** DRAFT. Do not send without coordinator approval. Lowest priority of
the fragment-class drafts — the Go team's documented stance is that a `#` in a
request-line target is malformed, so the vendor may consider rejection the
caller's or proxy's job.

**Vendor / component:** Go standard library `net/http` request parsing, surfaced
via the go-chi router.
**Our internal id:** ext-fw W14-F1 (also appears in kill/ext-routes as the
go-chi arm of the fragment class).
**Classification:** KNOWN-UNFIXED / arguably by-design. Same `#`-in-request-
target family as uvicorn/h11 and FrankenPHP/Caddy.

---

## 1. Summary

Behind nginx (which forwards a raw `#`), Go's `net/http` server keeps `#` and
everything after it as path characters, so go-chi's `{id}` parameter binds
`id = "acc-alice-1#frag"`. An RFC-3986 verifier drops the fragment and approves
`/api/v1/accounts/acc-alice-1`; the application binds a different id.

## 2. Affected version(s) / configuration

- `bh-exec-go-chi:latest` (Go `net/http` + chi router), placement edge behind
  nginx 1.30.7. Requires a proxy that forwards a raw `#` (nginx does;
  Envoy/Traefik/post-fix HAProxy reject it).

## 3. Impact (framed carefully)

Low: attacker controls only a suffix of the last path segment; a real
substitution needs app-side id normalization or a nested same-method route (we
showed the nested-route operation change on go-chi in ext-routes). No operation
change in the flat bench route space.

## 4. Minimal reproduction

```
GET /api/v1/accounts/acc-alice-1#frag HTTP/1.1
Host: api.bench.test
Authorization: DPoP <access-token>
DPoP: <proof: htm=GET, htu=http://api.bench.test/api/v1/accounts/acc-alice-1>

```

Observed: `id="acc-alice-1#frag"`, `getAccount` ran, HTTP 200. Local repro (from
`binding/harness`):

```sh
bash ../experiments/ext-fw/scripts/run_one_hostfix.sh w14-nginx-default-edge-go-chi-ovoff ../experiments/ext-fw/runs
```

Evidence: `binding/experiments/ext-fw/FINDINGS.csv` (W14-F1),
`ext-fw/runs/w14-nginx-*-edge-go-chi-ov*/hits.jsonl`,
`ext-fw/ddmin/w14-nginx-default-edge-go-chi-ovoff__getAccount_g2-fragment*.json`.

## 5. Suggested fix / mitigation

- Reject a bare `#` in the request-target, or document that `net/http` does not
  treat it as a fragment delimiter so routers/authorizers can account for it.
- Operators: front with a proxy that rejects `#` in the path.

## 6. References

- RFC 9112 §3.2; RFC 3986 §3.5.
- Go `net/url` `RawPath`/`EscapedPath` semantics (issue 14815 and related).
- Same class fixed by rejection in HAProxy (CVE-2023-45539).
