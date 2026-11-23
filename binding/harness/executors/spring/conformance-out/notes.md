**About the 2 failures (expected; not an executor defect).** W4's probe `allow override POST->DELETE` overrides with the
`X-HTTP-Method-Override` header only. Spring's standard mechanism, `HiddenHttpMethodFilter`, reads only the `_method`
request parameter. Spring has no built-in header override (see README). So the POST is routed as POST: no route matches,
the result is 404 NOT_FOUND, and under interpretation #4 the verifier is never called. This is the correct behaviour for Spring.
The equivalent check with Spring's own mechanism (form body `_method=DELETE`) was run by hand against the same
stub. Raw output is in `conformance-out/extra_form_override_verify/`:

| VERIFY_MODE | request | executor result | view sent to verifier |
|---|---|---|---|
| origin-raw | `POST /api/v1/accounts/acc-alice-1?x=1`, body `_method=DELETE` | 200 deleteAccount (raw POST, effective DELETE) | `POST /api/v1/accounts/acc-alice-1?x=1` |
| origin-routed | same | 200 deleteAccount | `DELETE /api/v1/accounts/acc-alice-1` |

stub log lines:
```
{"path": "/authz/orig", "method": "GET", "jti": "form-origin-raw", "x_original_method": "POST", "x_original_uri": "/api/v1/accounts/acc-alice-1?x=1", "x_original_host": "api.bench.test", "authorization": true, "dpop": true}
{"path": "/authz/orig", "method": "GET", "jti": "form-origin-routed", "x_original_method": "DELETE", "x_original_uri": "/api/v1/accounts/acc-alice-1", "x_original_host": "api.bench.test", "authorization": true, "dpop": true}
```
