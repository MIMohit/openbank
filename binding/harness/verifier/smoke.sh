#!/bin/bash
# Run from binding/harness. Smoke test all adapters of a running bh-verifier on $1 (default 127.0.0.1:19100) with minted headers.
V=${1:-127.0.0.1:19100}; PY=verifier/.venv/bin/python
U=http://api.bench.test/api/v1/accounts/acc-alice-1
mint() { $PY -m minter.cli mint --client alice --htm GET --htu $U "$@"; }
hdr() { echo "$1" | $PY -c "import json,sys;print(json.load(sys.stdin)['$2'])"; }
show() { echo "== $1"; curl -s -o /dev/stderr -w '   -> HTTP %{http_code}\n' "${@:2}" 2>&1 | sed 's/^/   /'; }
H=$(mint); A=$(hdr "$H" Authorization); D=$(hdr "$H" DPoP)
show "fwd allow" -D - -X POST http://$V/authz/fwd -H "X-Forwarded-Method: GET" -H "X-Forwarded-Proto: http" -H "X-Forwarded-Host: api.bench.test" -H "X-Forwarded-Uri: /api/v1/accounts/acc-alice-1?op=x" -H "Authorization: $A" -H "DPoP: $D"
show "fwd replay (same proof)" http://$V/authz/fwd -H "X-Forwarded-Method: GET" -H "X-Forwarded-Host: api.bench.test" -H "X-Forwarded-Uri: /api/v1/accounts/acc-alice-1" -H "Authorization: $A" -H "DPoP: $D"
H=$(mint); A=$(hdr "$H" Authorization); D=$(hdr "$H" DPoP)
show "orig allow" -D - http://$V/authz/orig -H "X-Original-Method: GET" -H "X-Original-URI: /api/v1/accounts/acc-alice-1" -H "X-Original-Host: api.bench.test" -H "Authorization: $A" -H "DPoP: $D"
H=$(mint); A=$(hdr "$H" Authorization); D=$(hdr "$H" DPoP)
show "orig deny (DELETE view)" -D - http://$V/authz/orig -H "X-Original-Method: DELETE" -H "X-Original-URI: /api/v1/accounts/acc-alice-1" -H "X-Original-Host: api.bench.test" -H "Authorization: $A" -H "DPoP: $D"
show "envoy allow" -D - "http://$V/authz/envoy/api/v1/accounts/acc-alice-1?x=1" -H "Host: api.bench.test" -H "Authorization: $A" -H "DPoP: $D"
H=$(mint); A=$(hdr "$H" Authorization); D=$(hdr "$H" DPoP)
show "envoy deny (DELETE)" -X DELETE "http://$V/authz/envoy/api/v1/accounts/acc-alice-1" -H "Host: api.bench.test" -H "Authorization: $A" -H "DPoP: $D"
H=$(mint --variant wrong_ath); A=$(hdr "$H" Authorization); D=$(hdr "$H" DPoP)
show "orig deny (wrong_ath)" http://$V/authz/orig -H "X-Original-Method: GET" -H "X-Original-URI: /api/v1/accounts/acc-alice-1" -H "X-Original-Host: api.bench.test" -H "Authorization: $A" -H "DPoP: $D"
H=$(mint --variant bearer_downgrade); A=$(hdr "$H" Authorization)
show "orig deny (bearer)" http://$V/authz/orig -H "X-Original-Method: GET" -H "X-Original-URI: /api/v1/accounts/acc-alice-1" -H "X-Original-Host: api.bench.test" -H "Authorization: $A"
