# DRAFT — NOT SENT. Private disclosure report (candidate)

**Status:** DRAFT. Do not send without coordinator approval.

**Vendor / component:** FrankenPHP (Caddy) request-target handling, surfaced via
Laravel / Symfony HttpFoundation routing.
**Our internal id:** ext-fw W14-F2.
**Classification:** KNOWN-UNFIXED (class). Same `#`-in-request-target family as
the uvicorn/h11 and Go net/http cases. The enabling step here is distinct: Caddy
**percent-encodes** the `#` into the path rather than rejecting it, and Symfony
then decodes it back into a route parameter.

---

## 1. Summary

Behind nginx (which forwards a raw `#`), FrankenPHP/Caddy does not reject a `#`
in the request-target and does not treat it as a fragment delimiter; it
percent-encodes it (the access log shows `raw_target
.../acc-alice-1%23frag`). Laravel/Symfony's router then percent-decodes it,
binding the route parameter `id = "acc-alice-1#frag"`. An RFC-3986 verifier
(e.g. RFC 9449 DPoP) drops the fragment and approves the base path
`/api/v1/accounts/acc-alice-1`, so the authorized view and the executed path
parameter differ.

## 2. Affected version(s) / configuration

- Laravel 12, symfony/http-foundation 7.4.23, PHP 8.3.37, FrankenPHP 1.14.0
  (`bh-exec-laravel:latest`), placement edge behind nginx 1.30.7.
- Requires a fronting proxy that forwards a raw `#` (nginx does; Envoy/Traefik/
  post-fix HAProxy reject it).

## 3. Impact (framed carefully)

Low, for the same reason as the uvicorn case: only a suffix of the last path
segment is attacker-controlled, so it is a resource/operation substitution only
when the app normalizes ids or when a nested same-method route catches the
suffix. No operation change occurs in the flat bench route space.

## 4. Minimal reproduction

```
GET /api/v1/accounts/acc-alice-1#frag HTTP/1.1
Host: api.bench.test
Authorization: DPoP <access-token>
DPoP: <proof: htm=GET, htu=http://api.bench.test/api/v1/accounts/acc-alice-1>

```

Observed: Caddy logs `raw_target=.../acc-alice-1%23frag`; Symfony binds
`id="acc-alice-1#frag"`; `getAccount` ran; HTTP 200. Local repro (from
`binding/harness`):

```sh
bash ../experiments/ext-fw/scripts/run_one_hostfix.sh w14-nginx-default-edge-laravel-ovoff ../experiments/ext-fw/runs
```

Evidence: `binding/experiments/ext-fw/FINDINGS.csv` (W14-F2),
`ext-fw/runs/w14-nginx-*-edge-laravel-ov*/hits.jsonl` (`g2-fragment`),
`ext-fw/ddmin/w14-nginx-default-edge-laravel-ovoff__getAccount_g2-fragment*.json`.

## 5. Suggested fix / mitigation

- **Caddy/FrankenPHP:** reject a bare `#` in the request-target (RFC 9112 §3.2)
  rather than percent-encoding it into the path; or expose the raw target so the
  application and any upstream authorizer agree on one representation.
- **Operators:** front with a proxy that rejects `#` in the path.

## 6. References

- RFC 9112 §3.2 (origin-form; `#` not permitted).
- RFC 3986 §3.5 (fragment not part of the request-target).
- Caddy/FrankenPHP: https://frankenphp.dev/ , https://caddyserver.com/docs/
- Symfony routing (percent-decoding of path parameters).
- Same class fixed by rejection in HAProxy (CVE-2023-45539).
