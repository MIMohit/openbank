# W22 real-application study — plan & design

## Goal
Answer the main reviewer objection ("synthetic route space"): do REAL OSS app route tables
turn our verifier/router differentials into real operation changes (A_leak, binding) or
path-policy bypasses (A_client, authorization)? Everything local in Docker, no hosted svc.

## Mechanisms to target (from GATE_DECISION.md / kill ROOT_CAUSES / ext-gw / e4)
- RC6 (G2, binding, A_leak): `#` kept in path by backend (uvicorn/h11, Go net/http, FrankenPHP),
  stripped as fragment by verifier. Needs NESTED same-method route `/{id}/<sub>`:
  proof bound to `GET /r/{id}`; attacker sends `GET /r/id#/sub` -> backend parses extra segment
  `sub` -> executes `/r/{id}/sub` (different op). nginx forwards `#` raw; Tomcat/Kestrel/Traefik/
  Envoy answer 400 to `#`.
- RC-W13-A (G2, APISIX forward-auth): verifier sees decoded path, raw `%2f` forwarded upstream.
- e4 RC1/RC2 (G2, authz, A_client): `/../` resolved by Kong upstream / ASP.NET Kestrel before
  routing while PDP authorizes raw target -> allow-list bypass. Also case-fold (ASP.NET/Express),
  `;` matrix (Spring), `//` collapse (Rails).
- G1 (by design): query dispatch, JSON body dispatch (e.g. GraphQL/JSON-RPC/MCP operationName),
  POST-only method override (Rails/Laravel by default).

## Oracle = the app's OWN route match / access log (not bench executor.jsonl)
A_leak hit: verifier allow for proof bound to base op AND app executes a DIFFERENT operation
(different matched route / handler / resource) than op(pi), status<400.
A_client hit: PDP allow (proof valid + path policy allow on raw view) AND app routes to a
FORBIDDEN resource/op (admin / other tenant), status<400.

## App selection (server stack -> mechanism), run one image at a time, <2GB resident
1. Gitea (Go net/http + chi) — A_leak `#` on nested API GET; A_client admin/other-user path policy.
2. HAPI FHIR JPA starter (Java/Tomcat) — textbook nested same-method routes + gateway auth;
   expect `#`->400 (negative), test `;`,`%2f`,`/../`,case for authz.
3. FastAPI/uvicorn app — reproduce `#` op-change on the exact stack RC6 was found, real routes.
4+ (time permitting): MCP server w/ OAuth (JSON-RPC body dispatch = G1); Rails/Laravel (POST
   override by default); Express (case-insensitive authz).

## Infra
Reuse bh-verifier:latest (HTU_CANON=rfc3986) and bh-pdp-* images already built. Write a per-app
docker-compose by hand (gateway=nginx/kong/apisix as relevant -> real app upstream, with
auth_request/forward-auth to the verifier/pdp). Reuse rawhttp.client + minter (headers_for) for
probes. Compose project + containers prefixed `w22-`. Tear down each app before the next.
