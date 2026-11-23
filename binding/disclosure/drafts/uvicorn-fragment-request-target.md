# DRAFT — NOT SENT. Private disclosure report (candidate)

**Status:** DRAFT. Do not send without coordinator approval.

**Vendor / component:** Uvicorn (`h11` protocol implementation). Related:
`h11`, Starlette/FastAPI routing.
**Our internal id:** kill RC6 (binding/experiments/kill); also realised as an
operation change in ext-routes class (1) / X1.
**Classification:** KNOWN-UNFIXED. The class (a `#` fragment delimiter kept in
the request-target path) is recognized: HAProxy fixed exactly this by rejecting
`#` in the path (CVE-2023-45539), and Envoy and Traefik return 400 for `#` in
the path. Uvicorn's `h11` path keeps it. We found no uvicorn/h11 security
advisory or fix; the limitation is noted in uvicorn discussion #1222.

---

## 1. Summary

Uvicorn, when using its pure-Python `h11` protocol implementation (the default
when `uvicorn[standard]`/`httptools` is not installed), does not strip a `#`
fragment from the HTTP request-target. It computes the ASGI `path`/`raw_path`
with `raw_path, _, query_string = event.target.partition(b"?")`
(`uvicorn/protocols/http/h11_impl.py`), splitting only on `?`. A request-target
such as `/api/v1/accounts/acc-alice-1#frag` therefore yields
`scope["path"] = "/api/v1/accounts/acc-alice-1#frag"`, and Starlette's `{id}`
converter binds `id = "acc-alice-1#frag"`.

Per RFC 9112 §3.2 the origin-form request-target is `absolute-path [ "?" query ]`
— a `#` is not permitted — and per RFC 3986 a `#` begins a fragment, which is not
part of the request-target at all. A security component that parses the target
per RFC 3986 (e.g. an RFC 9449 DPoP verifier, which excludes the fragment from
the bound view) will see the fragment-stripped path and approve it, while the
application binds a different path parameter value.

## 2. Affected version(s) / configuration

- uvicorn 0.54.0, h11 0.16.0, Starlette 1.10.0, FastAPI 0.165.0, **no
  `httptools`** (so the `h11` implementation is in use). With `httptools`,
  uvicorn uses `httptools.parse_url`, which splits the fragment (not measured
  here).
- Requires a fronting proxy that forwards a raw `#` upstream. nginx 1.30.7 does
  (with `proxy_pass` lacking a URI part, `$request_uri` is forwarded verbatim).
  Envoy v1.39.6 and Traefik v3.7.19 reject `#` in the path (400); HAProxy rejects
  it (CVE-2023-45539).

## 3. Impact (framed carefully)

Low on its own. The attacker controls only a **suffix of the last path segment**:
the executed resource id is `<bound-id>#<anything>`, not an arbitrary chosen
resource. It becomes a real substitution only when (a) the application normalizes
or truncates the id (e.g. prefix lookup, truncate at `#`), or (b) there is a
**nested same-method route** `/{id}/<sub>` that the kept suffix reaches. We
demonstrated (b) in a richer route space (ext-routes): with a nested route
`DELETE /accounts/{id}/statements/{sid}`, a proof accepted for
`deleteAccount` executes `deleteStatement` — a genuine *operation*-binding break
on a default nginx + FastAPI stack. The value of this report is that it enables
that composition; the practical severity in a flat route space is low.

## 4. Minimal reproduction

```
GET /api/v1/accounts/acc-alice-1#frag HTTP/1.1
Host: api.bench.test
Authorization: DPoP <access-token>
DPoP: <proof: htm=GET, htu=http://api.bench.test/api/v1/accounts/acc-alice-1>

```

Observed: `#frag` retained in `scope["path"]`; `path_params.id =
"acc-alice-1#frag"`; handler ran; HTTP 200. Direct-to-executor (no gateway)
reproduces the parsing. Local repro (from `binding/harness`):

```sh
bash ../experiments/kill/scripts/run_one.sh w9-nginx-default-edge-fastapi-ovoff
```

Evidence: `binding/experiments/kill/FINDINGS.csv` (F1), `kill/ROOT_CAUSES.md`
RC6, `kill/ddmin/`, `kill/groundtruth/raw/fastapi-ov*/executor.all.jsonl`
(same behavior without a gateway).

## 5. Suggested fix / mitigation

- **Uvicorn (h11 path):** split the request-target on `#` as well as `?`, or
  reject a target containing a bare `#` (RFC 9112 §3.2), matching the httptools
  path and HAProxy's post-CVE-2023-45539 behavior.
- **Operators:** put a proxy that rejects `#` in the path in front (Envoy,
  Traefik, post-fix HAProxy), or install `uvicorn[standard]` (httptools).

## 6. References

- Source: `uvicorn/protocols/http/h11_impl.py` (target partition on `?` only).
- Uvicorn discussion #1222 (uvicorn handles only origin-form of the h11 target):
  https://github.com/encode/uvicorn/discussions/1222
- RFC 9112 §3.2 (origin-form): https://www.rfc-editor.org/rfc/rfc9112#section-3.2
- RFC 3986 §3.5 (fragment is not part of the request-target).
- Same class fixed in HAProxy — CVE-2023-45539 (reject `#` in URI path):
  https://git.almalinux.org/rpms/haproxy/raw/branch/c8s/CVE-2023-45539-reject-pound-char-URI-component.patch
