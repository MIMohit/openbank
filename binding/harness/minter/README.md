# Minter (W3)

A test authorization server and client for the harness. It provides:
- **Keys:** ES256 keys for the AS and for the clients alice and bob.
- **Access tokens:** RFC 9068 tokens with `cnf.jkt` (CONTRACT §2).
- **DPoP proofs:** RFC 9449 proofs, with full control over every header and claim, including deliberately malformed variants.
- **E6 signers:** RFC 9421 and draft-cavage request signers (each with a matching verifier).

Dependencies: Python 3.12 and `cryptography==44.0.2` (`requirements.txt`). Run everything from `binding/harness/`, or put that directory on `PYTHONPATH`. The keys directory is `$BH_KEYS_DIR`, defaulting to `binding/harness/keys`.

## Keys
```sh
python -m minter.keys            # generates once; never overwrites without --force
```
This writes the following files to `keys/`:
- `as_priv.jwk` and `as_pub.jwk`
- `client_alice.jwk` and `client_bob.jwk` (private, mode 0600)
- `client_<name>.pub.jwk`

Each JWK's `kid` is its RFC 7638 thumbprint. `keys/.gitignore` admits only the public files to git. The private keys are local to this machine: if they are regenerated, every component that baked in `as_pub.jwk` (for example the `bh-verifier` image) must be rebuilt.

Thumbprints of the current key set (generated 2026-11-23):
- alice: jkt `lxZXvDIoYZzbolMbWIWBOOEdz9dZQozbmTa1zdXUgTc`
- bob: jkt `8XHdm-as6tnB8DaNGOQZPZXBk9AIiwbYRO2Q6FuyZH8`
- AS: kid `vIOiJFgMKQzPaJf11EzNf4AjKIODrNAN1EzrBOARTTw`

## CLI
```sh
python -m minter.cli mint --client alice --htm GET --htu http://api.bench.test/api/v1/accounts/acc-alice-1
# {"Authorization": "DPoP eyJ...", "DPoP": "eyJ...", "jti": "...", "htm": "GET", "htu": "...", "client": "alice", "variant": "valid"}
python -m minter.cli mint ... --variant wrong_ath     # any proof or request variant
python -m minter.cli mint ... --at <token> --jti fixed-jti --iat-offset -30
python -m minter.cli token --client bob
python -m minter.cli variants
```
Request variants change the shape of the request rather than the proof:
- `multiple_dpop`: `DPoP` is a list of two proofs.
- `no_dpop`: the `DPoP` header is omitted.
- `bearer_downgrade`: `Authorization: Bearer`, with no DPoP header.
- `reused_jti`: a normal proof; the caller sends it twice.

## Library
```python
from minter.tokens import mint_access_token
from minter.dpop import mint_proof, mint_variant, headers_for, VARIANTS
from minter import keys as K
at = mint_access_token("alice", exp=..., aud=..., cnf_jkt=..., typ=..., as_key=...)   # every claim overridable
proof = mint_proof(K.client_key("alice"), "GET", htu, at,
                   typ=..., alg=..., jwk=..., ath=..., include_ath=False, iat_offset=..., jti=...,
                   header_extra={...}, claims_extra={...}, header_drop=[...], claims_drop=[...],
                   sign_key=other_key, sign_alg="none"|"HS256", signature="...", corrupt_signature=True)
headers = headers_for("alice", "POST", htu, variant="different_key")   # {"Authorization":..., "DPoP":...}
```
Proof variants (`VARIANTS`):
- `valid`
- missing members: `missing_typ`, `missing_alg`, `missing_jwk`, `missing_jti`, `missing_htm`, `missing_htu`, `missing_iat`, `missing_ath`
- header: `wrong_typ`, `alg_none`, `alg_hs256` (HMAC keyed with the public-JWK JSON), `bad_signature`, `private_key_in_jwk`
- method: `wrong_htm` (PUT, or POST when the base is PUT), `lowercase_htm`
- URI: `wrong_htu` (+ "ohnonotagain", as in OIDF)
- time: `iat_future_1h`, `iat_past_1h`
- binding: `wrong_ath`, `different_key` (proof by bob for alice's token), `jwk_signature_mismatch` (header jwk ≠ signing key)
- should be accepted: `extra_claims`, `htu_with_query`, `htu_with_fragment`, `htu_upper_scheme_host`, `htu_default_port`

## E6 signers
- `rfc9421.py` signs with `ecdsa-p256-sha256` (raw r‖s, as in RFC 9421 §3.3.4).
  - Supported derived components: `@method`, `@target-uri`, `@authority`, `@scheme`, `@request-target`, `@path`, `@query`.
  - Header fields are supported, with `Content-Digest` per RFC 9530.
  - Coverage profiles (`COVERAGE`):
    - `full` (default): `@method @target-uri content-digest`, which binds what the executor dispatches on
    - `method-path-query`
    - `method-target`
    - `target-only` (no method)
    - `path-only` (no method, no query)
    - `authority-path`
    - `digest-only`
  - `verify_request(..., required=[...])` models a verifier coverage policy.
  - Not implemented: the `;sf`/`;key`/`;bs`/`;req`/`;tr` parameters and `@query-param`.
- `cavage.py` implements draft-cavage-http-signatures-12 with `algorithm="hs2019"`. Signatures are ECDSA P-256 SHA-256, DER-encoded: the draft does not fix the encoding, and DER is what the common Java and Node libraries emit. Profiles:
  - `berlin-group`: `digest x-request-id date`. No `(request-target)`, so the signature replays across endpoints and methods; a test demonstrates this.
  - `with-target`: `(request-target) host date digest`.
  - `date-only`.

## Test
The minter is tested in `../verifier/tests/test_minter.py`, and indirectly by every verifier test. See `../verifier/README.md`.

## Known limitations
- EC P-256 client and AS keys only. There is no RSA client key, so the OIDF "RS256 with an RSA client key" case is not applicable.
- No DPoP nonce claim helper beyond `claims_extra={"nonce": ...}`.
- The cavage signer is ECDSA only, while Berlin Group deployments use RSA certificates. Coverage semantics, which are what E6 studies, do not depend on the algorithm.
