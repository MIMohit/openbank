"""Minter interface shim (CONTRACT §2, §6).

W3 owns `harness/minter/`. Until it exists, this shim provides the SAME capability the
runner needs: mint a fresh access token + DPoP proof bound to a base op's canonical
(htm, htu) for a given client. It implements RFC 9449 / the §2 token+proof formats with
ES256, so the proofs are real and will verify against a conforming verifier.

Interface the runner depends on (documented as a contract interpretation in the README):
    minter = get_minter()
    at, proof, jti = minter.mint(client="alice", htm="GET", htu="http://.../api/v1/accounts/acc-alice-1")

The runner prefers the real W3 minter if importable (see runner.minter_adapter).

Keys: to avoid writing into W3's `harness/keys/` (not owned by W7), this shim keeps its
own ephemeral keypairs under `runner/.shimkeys/`. These are TEST keys only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
import uuid
from typing import Dict, Tuple

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import hashes, serialization

SHIM_KEYS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".shimkeys")

ISS = "https://as.bench.test"
AUD = "https://api.bench.test"

OWNERS = {"alice": "acc-alice-1", "bob": "acc-bob-1"}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_json(obj) -> str:
    return _b64url(json.dumps(obj, separators=(",", ":"), sort_keys=False).encode())


def _ec_jwk_public(pub: ec.EllipticCurvePublicKey) -> Dict[str, str]:
    numbers = pub.public_numbers()
    x = numbers.x.to_bytes(32, "big")
    y = numbers.y.to_bytes(32, "big")
    return {"kty": "EC", "crv": "P-256", "x": _b64url(x), "y": _b64url(y)}


def _jwk_thumbprint(jwk: Dict[str, str]) -> str:
    # RFC 7638: lexicographic members for EC = crv, kty, x, y
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"), sort_keys=True).encode()
    return _b64url(hashlib.sha256(canonical).digest())


def _es256_sign(priv: ec.EllipticCurvePrivateKey, signing_input: bytes) -> bytes:
    der = priv.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _jws(header: dict, payload: dict, priv: ec.EllipticCurvePrivateKey) -> str:
    signing_input = (_b64url_json(header) + "." + _b64url_json(payload)).encode("ascii")
    sig = _es256_sign(priv, signing_input)
    return signing_input.decode("ascii") + "." + _b64url(sig)


def _load_or_create_key(path: str) -> ec.EllipticCurvePrivateKey:
    if os.path.exists(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    return key


class ShimMinter:
    """Reference minter used when W3's is unavailable."""

    def __init__(self):
        self.as_key = _load_or_create_key(os.path.join(SHIM_KEYS_DIR, "as_priv.pem"))
        self.client_keys = {
            name: _load_or_create_key(os.path.join(SHIM_KEYS_DIR, f"client_{name}.pem"))
            for name in OWNERS
        }

    def client_jkt(self, client: str) -> str:
        jwk = _ec_jwk_public(self.client_keys[client].public_key())
        return _jwk_thumbprint(jwk)

    def mint_access_token(self, client: str, scope: str = "accounts transfers") -> str:
        now = int(time.time())
        header = {"alg": "ES256", "typ": "at+jwt"}
        payload = {
            "iss": ISS, "aud": AUD, "sub": client, "scope": scope,
            "iat": now, "exp": now + 3600, "jti": "at-" + uuid.uuid4().hex,
            "cnf": {"jkt": self.client_jkt(client)},
        }
        return _jws(header, payload, self.as_key)

    def mint_proof(self, client: str, htm: str, htu: str, access_token: str) -> Tuple[str, str]:
        now = int(time.time())
        jti = str(uuid.uuid4())
        pub_jwk = _ec_jwk_public(self.client_keys[client].public_key())
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": pub_jwk}
        ath = _b64url(hashlib.sha256(access_token.encode()).digest())
        payload = {"jti": jti, "htm": htm, "htu": htu, "iat": now, "ath": ath}
        proof = _jws(header, payload, self.client_keys[client])
        return proof, jti

    def mint(self, client: str, htm: str, htu: str,
             scope: str = "accounts transfers") -> Tuple[str, str, str]:
        """Return (access_token, dpop_proof, jti) bound to (htm, htu) for `client`."""
        at = self.mint_access_token(client, scope)
        proof, jti = self.mint_proof(client, htm, htu, at)
        return at, proof, jti

    # Public key export so a verifier/test can check signatures.
    def as_public_jwk(self) -> Dict[str, str]:
        return _ec_jwk_public(self.as_key.public_key())


_SINGLETON = None


def get_shim_minter() -> ShimMinter:
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = ShimMinter()
    return _SINGLETON
