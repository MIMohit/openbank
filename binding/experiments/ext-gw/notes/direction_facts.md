# Gateway view/execution direction facts (from smoke + config read)

Verified from rendered configs (gateways/*/rendered/{default,recommended}-edge) and the
default×fastapi×ovoff smoke runs. "view" = what the verifier sees; "upstream" = what the executor's raw_target shows.

## Kong 3.9.5 (pre-function -> /authz/orig)
- Verifier view = `ngx.var.request_uri` = **RAW** target (no gateway normalisation applied to the view).
- Upstream = Kong router's **normalised** path (built-in, not configurable).
- Host: default `preserve_host:false` -> executor sees `Host: executor:8080`; recommended `preserve_host:true` -> keeps api.bench.test.
- `underscores_in_headers`: default **on** (hard-coded in kong nginx template); recommended overrides proxy block to off.
- Fragment `#`: Kong ACCEPTS `#` in target, forwards it RAW upstream. Verifier (RFC3986) strips `#` -> allow.
  uvicorn/h11 keeps `#frag` in path -> `{id}=acc-alice-1#frag` => **RC6 resource substitution (G2)**, same mechanism as nginx RC6. fastapi only.
- dot-literal `/./`: verifier RFC3986-normalises -> allow; Kong router normalises upstream too -> executes sound op (NOT a hit).
- dotdot `/../`, double-slash: verifier RFC3986 collapses -> htu mismatch -> **deny**. Safe.

## APISIX 3.21.0 (forward-auth -> /authz/fwd, X-Forwarded-Uri)
- Verifier view = `ctx.var.request_uri` = APISIX **NORMALISED** uri (APISIX overwrites it before plugins run).
- Upstream = **RAW** path (`real_request_uri` kept; raw double-slash reaches executor).  ==> ANSWER to brief: APISIX forwards the RAW path upstream while the verifier sees the NORMALISED path. Opposite direction from Kong/NGINX.
- Evidence (default fastapi): `g2-double-slash-mid` view `/api/v1/accounts/acc-alice-1` (merged) => allow; exec_raw `/api//v1/accounts/acc-alice-1` => NOT_FOUND. Genuine split, but latent in bench route space (no route matches raw double-slash) -> no op change.
- dotdot `/../`: APISIX normalises the VIEW -> htu mismatch -> deny (safe here).
- Fragment `#`: APISIX strips `#` from the view it shows verifier (allow) but forwards `#frag` upstream in the QUERY position -> uvicorn keeps it -> `op=freeze#frag` => accountAction.unknown. G1 effect (query already unbound), G2 vehicle. = RC7 analog.
- `underscores_in_headers`: default on; recommended off.

## HAProxy 3.2.27 (Lua core.httpclient -> /authz/orig)
- Verifier view = `txn.f:url()` = target as currently held. Default = NO normalize-uri -> raw; recommended runs `normalize-uri {fragment-strip,path-strip-dotdot,path-merge-slashes,percent-decode-unreserved,percent-to-uppercase}` BEFORE bh_authz, so verifier AND upstream see the SAME normalised URI.
- Fragment `#`: HAProxy default **REJECTS** `#` in request target (no verifier call, NOEXEC) -> no fragment G2. (like traefik/envoy.) recommended fragment-strip also removes it.
- dot-literal `/./`: default verifier gets raw -> RFC3986 allow; upstream raw `/./` -> Starlette NOT_FOUND = latent L1 (allow->404, no op change). recommended path-strip-dotdot normalises both sides -> sound.
- Host preserved (api.bench.test) in both profiles. recommended adds `option http-restrict-req-hdr-names delete`.

## Consequence for the gate (G2/G3 with resolution>1)
- Kong RC6 (fragment resource substitution, fastapi/uvicorn) = SAME binding-failure class as nginx RC6, now on a 4th gateway. Prevalence, not a new independent class.
- APISIX normalised-view / raw-upstream split and HAProxy/Kong dot-segment = NEW *latent* G2 differentials but produce only NOT_FOUND (res stays 1) in the bench route space. Not gate-qualifying.
- G3: Kong/APISIX/HAProxy default forward client cert headers (x-forwarded-client-cert, x-client-cert, client-cert) and spoofed x-verified-view to the executor = propagation (matters only if a backend trusts them), NOT operation-change binding hits. x-verified-sub/jkt are overwritten by the gateway from the authz response (sound); the x-verified-sub:alice marker is the known oracle artefact.
