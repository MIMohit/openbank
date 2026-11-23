# Gate G1, final decision (coordinator, after the extension round)

**Decision: PASS.** The CONTRACT §12 hard-kill bar (at least 2 independent G2/G3 classes on current releases, under default or documented configurations) is met. The paper keeps the binding-soundness framing. The weight of the evidence has shifted toward G2 and authorization soundness, and G1 rests on prevalence data.

## Evidence, with independence counted by mechanism (resolving component × differential), not by worker

### Binding soundness (A_leak: one leaked proof; the executor runs an operation other than op(π))
| Mechanism | Sources | Classes |
|---|---|---|
| `#` kept in the path by the backend server while the verifier strips it as a fragment (nginx forwards it raw). Backends: uvicorn/h11, Go net/http, FrankenPHP. With nested routes it changes the **operation** (getAccount → getStatements). | kill RC6, ext-routes class 1, ext-gw RC-W13-B, ext-fw | **1 mechanism** (several servers) |
| APISIX forward-auth gives the verifier the *decoded* path and forwards the raw `%2f` upstream | ext-gw RC-W13-A | **1 (new)** |
| Dot-segment path reaching a catch-all route that the proof did not cover | ext-routes class 2 | 1 (low practical impact) |

### Authorization soundness (A_client: a valid own proof; a path policy is split from the executor)
| Mechanism | Breaks a strict allow-list? |
|---|---|
| Kong authorizes the raw target but normalises it upstream: `/../` (e4 RC2) | **yes** |
| Kong, the same split for `//` (e4 RC7) | no |
| ASP.NET/Kestrel resolves `/../` before routing (e4 RC1) | **yes** |
| ASP.NET case-insensitive routing (RC3), Express case-insensitive routing (RC4), Spring strips `;` matrix params (RC5), Rails collapses `//` (RC6) | no (blocklist policies only) |

### G1 (by design: proof-bound under-binding)
- Query or body dispatch changes the operation on every tested stack.
- **POST-only override:** a `postAccount` proof leads to PUT/DELETE in all 8 frameworks when override is enabled. Rails (non-API app) and Laravel do this **by default**; Laravel has no off-switch (ext-routes, ext-fw).
- Prevalence: see `binding/prevalence/`.

### G3
- No binding hits.
- Client-cert/XFCC and `X-Verified-View` header propagation through the gateways is a *conditional* authorization issue: it matters only if the backend trusts those headers.
- `X-Verified-Sub` spoofing is blocked by every gateway tested.
- Open: the absolute-form target and `X-Original-URL` / `X-Rewrite-URL` were not in the E4 battery.

### A3 (verifier placement, ext-fw)
Verifying at the application with the raw target (origin-raw) removes neither the G1 dispatch/override hits nor the `#` differential. The zeros for nginx-origin and `both` were harness artefacts (Host rewrite, shared one-time jti) and are documented.

## Caveats the paper must carry
- RC3–RC6 resemble known path-normalisation CVEs (Istio, Traefik). Present them as prevalence evidence, not as discoveries.
- Novelty of the Kong and APISIX findings is **unverified** until the prior-art and advisory triage is done.
- G2 authorization findings require a path-based policy at the gateway, and the DPoP check itself passes. The paper states this explicitly.
- The route space is synthetic (bench API v1/v2). Whether real applications contain routes that turn these differentials into impact is argued from the prevalence data (E1/E2), not measured.
