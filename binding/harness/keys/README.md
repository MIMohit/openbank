# Harness keys (owned by W3)

Generated once with `python -m minter.keys` (from `binding/harness/`). The files are:
- `as_pub.jwk`: the test AS ES256 public key, used by the verifier to check access tokens.
- `as_priv.jwk`: the AS private key. Not committed.
- `client_alice.jwk` and `client_bob.jwk`: the clients' DPoP private keys. Not committed.
- `client_<name>.pub.jwk`: the clients' public keys.

Each JWK's `kid` is its RFC 7638 thumbprint. `.gitignore` admits only the public files. If the keys are regenerated, rebuild `bh-verifier:latest`, which bakes in `as_pub.jwk`.
