# Reference DPoP verifier (W3)

A reference resource-server verifier for RFC 9449 DPoP. It runs every proof check in RFC 9449 §4.3 and the resource-server checks in §7, against a *view* of the client request (method, URI, host, proto). Adapters build that view from what a gateway forwards. It ships in two forms:

- a library: `verifier.core.verify(view, headers, config) -> Decision`, used by the unit tests and the mutator;
- an HTTP service on :9100, built as the docker image `bh-verifier:latest` (CONTRACT §4).

Dependencies: Python 3.12 and `cryptography==44.0.2` (pinned in `requirements.txt`). The service uses only stdlib `http.server` (`ThreadingHTTPServer`, HTTP/1.1 keep-alive). Base image: `python:3.12.8-slim-bookworm`.

## Files
| file | purpose |
|---|---|
| `core.py` | `View`, `Config` (`Config.from_env()`), `Decision`, `JtiCache`, `verify()`, `view_mac()` |
| `canon.py` | `HTU_CANON` modes `rfc3986`, `none`, `strict`; `remove_dot_segments` (RFC 3986 §5.2.4) |
| `jose.py` | strict base64url, compact-JWS parsing, RFC 7638 thumbprints, ES256/384/512, RS256 and PS256 verification |
| `server.py` | the adapters `/authz/fwd`, `/authz/orig` and `/authz/envoy/{rest}`, plus `/health`; JSONL log |
| `Dockerfile`, `Dockerfile.dockerignore` | image build (context = `binding/harness`) |
| `smoke.sh`, `smoke_output.txt` | curl smoke test of a running container, and its recorded raw output |
| `tests/` | pytest suite (125 tests) |

## Run
```sh
cd binding/harness
python -m minter.keys                                   # once; creates keys/ (see ../minter/README.md)
docker build -f verifier/Dockerfile -t bh-verifier:latest .
docker run -d --name w3-verifier --memory 256m -p 127.0.0.1:19100:9100 \
  -e HTU_CANON=rfc3986 -e VIEW_MAC=on -e VIEW_MAC_KEY=k -v "$PWD/logs/x:/logs" bh-verifier:latest
verifier/smoke.sh 127.0.0.1:19100
# without docker:
PYTHONPATH=. AS_PUB_JWK=keys/as_pub.jwk LOG_PATH=/tmp/v.jsonl python -m verifier.server
```
The image bakes in `keys/as_pub.jwk` as it was at build time. If the keys are regenerated, rebuild the image or mount the new key and point `AS_PUB_JWK` at it.

Environment variables: `HTU_CANON=rfc3986|none|strict` (default rfc3986), `JTI_CACHE=on|off` (on), `IAT_WINDOW` (60 s), `VIEW_MAC=on|off` (off), `VIEW_MAC_KEY`, `AS_PUB_JWK` (/app/keys/as_pub.jwk), `PORT` (9100), `LOG_PATH` (/logs/verifier.jsonl), `LOG_STDOUT=on|off` (on), `VIEW_DUP=first|last|reject` (first; see the interpretations below), `EXPECTED_ISS`, `EXPECTED_AUD`.

## Adapters
| route | view source |
|---|---|
| `ANY /authz/fwd` | `X-Forwarded-Method`, `-Proto` (default http), `-Host`, `-Uri` |
| `ANY /authz/orig` | `X-Original-Method`, `-URI`, `-Host` (falls back to `Host`), `-Proto` (default http) |
| `ANY /authz/envoy/{rest}` | the request method; URI = raw request target minus `/authz/envoy`; host = `Host` (Envoy forwards the original `:authority`); proto = `X-Forwarded-Proto` or http |
| `GET /health` | `{"status":"ok","canon":...}` |

- Allow: 200, with `X-Verified-Sub`, `X-Verified-Jkt` and, when `VIEW_MAC=on`, `X-Verified-View`.
- Deny: 401, with `WWW-Authenticate: DPoP error="invalid_dpop_proof"|"invalid_token", algs="..."` and the body `{"decision":"deny","reason":<code>,"error":...}`.
- Any request body is read and discarded.
- If a view header is missing, the verifier fails closed with the reason `view_missing`.

Note for W6 (Envoy): the ext_authz `http_service.authorization_request.allowed_headers` must include `authorization` and `dpop` (Envoy forwards only a few headers by default), and `allowed_upstream_headers` should list `x-verified-*`.

## Checks and reason codes (in evaluation order)
| check | spec | reason | error |
|---|---|---|---|
| view reconstructed | (adapter) | `view_missing` | invalid_dpop_proof |
| one Authorization header, `DPoP` scheme (case-insensitive), no Bearer downgrade | §7.1, §7.2 | `auth_missing`, `auth_multiple`, `auth_malformed`, `bearer_downgrade`, `auth_scheme_unsupported` | invalid_token |
| exactly one DPoP header (comma-joined counts as several) | §4.3 (1) | `dpop_missing`, `dpop_multiple` | invalid_dpop_proof |
| well-formed JWS (strict base64url, JSON objects) | §4.3 (2) | `dpop_malformed` | " |
| `typ`, `alg`, `jwk` present | §4.3 (3) | `missing_typ` / `missing_alg` / `missing_jwk` | " |
| `typ` = dpop+jwt | §4.3 (4) | `wrong_typ` | " |
| alg asymmetric, not none, supported | §4.3 (5) | `alg_none`, `alg_symmetric`, `alg_unsupported` | " |
| jwk public only, valid, matches alg | §4.3 (7) | `jwk_private`, `jwk_invalid` | " |
| signature verifies with jwk | §4.3 (6) | `bad_signature` | " |
| `jti`, `htm`, `htu`, `iat` present and well-typed | §4.3 (3) | `missing_jti` / `_htm` / `_htu` / `_iat` | " |
| htm == view method (case-sensitive) | §4.3 (8) | `htm_mismatch` | " |
| htu matches the view URL under HTU_CANON, ignoring query and fragment | §4.3 (9) | `htu_mismatch`, `htu_invalid`, `view_invalid`, `strict_*`, `htu_strict_*` | " |
| \|now − iat\| ≤ IAT_WINDOW | §4.3 (11) | `iat_skew` | " |
| AT: compact JWS, typ at+jwt, alg = AS key alg, signature against as_pub.jwk, iss, aud (string or list), exp, nbf | §7, RFC 9068 | `token_malformed`, `token_typ`, `token_alg`, `token_signature`, `token_iss`, `token_aud`, `token_expired`, `token_nbf` | invalid_token |
| ath present and equal to b64url(SHA-256(AT)) | §4.3 (10), §7 | `missing_ath`, `ath_mismatch` | invalid_dpop_proof |
| cnf.jkt present and equal to the thumbprint of the proof jwk | §4.3 (12), §6.1 | `token_no_cnf`, `jkt_mismatch` | invalid_token |
| jti not seen before (if JTI_CACHE=on) | §11.1 | `jti_replay` | invalid_dpop_proof |

## HTU_CANON
Every mode strips the query and fragment from both htu and the view URL first. The view URL is `proto://host` + the view URI, or the URI itself if it is in absolute form.
- `none`: exact string equality.
- `rfc3986`: applied to both sides, then compared. Syntax-based normalisation (RFC 3986 §6.2.2): lower-case scheme and host, upper-case percent-encoding hex, decode percent-encoded unreserved characters, `remove_dot_segments`. Scheme-based normalisation (§6.2.3): drop the default or empty port, and an empty path becomes `/`. `%2F` is not decoded, `//` is not collapsed and path case is preserved.
- `strict`: first rejects a view or htu whose path contains any of the following, then compares as in rfc3986. The match is therefore still case- and default-port-tolerant on scheme and host.
  - a dot-segment, raw or `%2E`-encoded
  - `//`
  - `%2F` or `%5C`
  - `\`
  - `%00`
  - `%25`
  - `;`
  - an encoded unreserved character
  - lower-case hex
  - a malformed `%`
  - a control, space or non-ASCII character
  - userinfo

  The test matrix in `tests/test_canon.py` gives the expected decision for each mode on each input.

## Test
```sh
cd binding/harness
python3.12 -m venv verifier/.venv && verifier/.venv/bin/pip install -r verifier/requirements-dev.txt
PYTHONPATH=. verifier/.venv/bin/python -m pytest -q verifier/tests
```
The tests generate their own key set in a temp dir (`BH_KEYS_DIR`), so they never touch `keys/`.

Last run (2026-11-23, Python 3.12.13, cryptography 44.0.2, pytest 8.3.5, macOS): **125 passed, 0 failed**.
- `test_core.py`: the positive case, plus one negative test per OIDF FAPI2 DPoP negative item. The OIDF items are:
  - multiple DPoP headers
  - malformed proof
  - missing typ, alg, jwk, jti, htm, htu, iat or ath
  - wrong typ
  - alg none, plus HS256
  - bad signature
  - private key in jwk
  - htm PUT
  - htu + "ohnonotagain"
  - iat ±1 h
  - reused jti
  - wrong ath
  - different key
  - no DPoP header
  - Bearer downgrade

  It also checks that extra claims and an htu carrying a query or fragment are accepted. Beyond the OIDF list it covers the access-token negatives, Bearer with a proof attached, a jti not burned on denial, the iat window edges, the DPoP scheme in all caps, and VIEW_MAC.
- `test_canon.py`: a 13-input × 3-mode matrix covering case and default-port variants, dot-segments, encoded slashes, duplicate slashes and path parameters. Also the strict reason codes and the RFC 3986 examples.
- `test_adapters.py`: the real HTTP server in-process. It exercises each of the three adapters (allow, deny and view extraction), the JSONL log fields, fail-closed on a missing view, raw target handling for Envoy, the request-level variants over HTTP, replay over HTTP, the `VIEW_DUP` policies and keep-alive with a body.
- `test_minter.py`: keys, thumbprints (the RFC 7638 RSA vector), token and proof shape, the CLI, and RFC 9421 and cavage round trips plus their under-binding behaviour.

Container smoke test (2026-11-23, image `sha256:263f3231d20f…`): `smoke.sh` against `w3-verifier-smoke`, with VIEW_MAC=on. Results: fwd, orig and envoy allow, with `X-Verified-*` set; 5 expected denials: `jti_replay`, `htm_mismatch` (orig and envoy), `ath_mismatch` and `bearer_downgrade`. Raw output is in `smoke_output.txt`. The container was removed afterwards.

## Contract interpretations
1. **Query and fragment are stripped in every canon mode**, `none` included. `none` means no normalisation, but RFC 9449 §4.3 defines the htu comparison without query and fragment, and OIDF expects acceptance in that case.
2. **VIEW_MAC `canon(view_uri without query)`** is the *path only*, normalised as in rfc3986 (no scheme or host), whatever HTU_CANON is set to. An executor can recompute it from its routed path. The key is the UTF-8 bytes of `VIEW_MAC_KEY`, the MAC is unpadded base64url, and `view_method` is upper-cased as specified. `verifier.core.view_mac(key, jti, method, uri, jkt)` is the reference implementation. `VIEW_MAC=on` with an empty key refuses to start.
3. **Duplicate view headers** (G3), for example a client-supplied `X-Forwarded-Uri` plus the gateway's: the contract does not say which copy wins. The default `VIEW_DUP=first` mimics the common `Header.Get`-style behaviour, so the verifier does not mask gateway propagation bugs. `last` and `reject` are available. Every log line has `view_dup: true|false`.
4. **The jti is recorded only when the request is allowed.** A proof denied for a view mismatch can still be used later against the right view. This matches the RFC intent (a replay is a reuse of an accepted proof) and stops denied probes from burning jtis. jti cache TTL = 2·IAT_WINDOW + 5 s. The key is the jti string alone.
5. **typ comparisons are case-insensitive** (media-type semantics, RFC 7515 §4.1.9): `dpop+jwt`, and `at+jwt` / `application/at+jwt`. htm is compared case-sensitively.
6. **Error codes:** token, scheme, cnf and Bearer problems map to `invalid_token`; everything about the proof, including a missing DPoP header, maps to `invalid_dpop_proof`. No `use_dpop_nonce`: nonces are not implemented.
7. **Envoy adapter:** a target of `/authz/envoy?x` maps to the view `/?x`. Host comes from `Host`, because the ext_authz check request carries the original authority.
8. **Extra log fields** beyond the CONTRACT schema: `view_proto`, `view_dup`, `status`, `latency_us`. The `jti` field holds the proof's jti, or the unverified payload jti when the proof failed before its signature was checked, or null.
9. **Supported proof algs:** ES256, ES384, ES512, RS256 (RSA ≥ 2048 bits) and PS256. The AS token alg must equal the `alg` in `as_pub.jwk` (ES256).

## Known limitations
- No DPoP server nonces (`use_dpop_nonce`) and no `nbf`/`exp` checks on the proof itself (the OIDF module `CheckDpopProofNbfExp` is not mirrored).
- The jti cache is per-process and in memory, so a multi-replica deployment would not share it. This is deliberate: it matches RFC 9449 §11.1's latitude.
- The TLS, mTLS and `cnf.x5t#S256` paths are out of scope (CONTRACT §1).
- `http.server` rejects some malformed request lines before the adapters see them. Gateways send well-formed check requests, so this is irrelevant behind a gateway, but direct raw-socket fuzzing of the verifier is not what it is for.
