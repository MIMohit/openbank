"""Minimal JOSE helpers for the minter (stdlib + cryptography only).

Kept separate from verifier/jose.py on purpose: the minter must be able to produce
inputs the verifier rejects, so it never reuses verifier-side validation.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u_json(obj: Any) -> str:
    return b64u(json.dumps(obj, separators=(",", ":")).encode())


def _int_b64u(n: int, length: int) -> str:
    return b64u(n.to_bytes(length, "big"))


def ec_private_to_jwk(key: ec.EllipticCurvePrivateKey) -> dict:
    nums = key.private_numbers()
    pub = nums.public_numbers
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _int_b64u(pub.x, 32),
        "y": _int_b64u(pub.y, 32),
        "d": _int_b64u(nums.private_value, 32),
    }


def public_jwk(jwk: dict) -> dict:
    """Strip private members (and non-key metadata other than kty/crv/x/y/kid)."""
    return {k: jwk[k] for k in ("kty", "crv", "x", "y", "kid") if k in jwk}


def thumbprint(jwk: dict) -> str:
    """RFC 7638 SHA-256 JWK thumbprint (EC keys)."""
    if jwk.get("kty") != "EC":
        raise ValueError("only EC keys supported")
    req = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    canon = json.dumps(req, separators=(",", ":"), sort_keys=True).encode()
    return b64u(hashlib.sha256(canon).digest())


def private_key_from_jwk(jwk: dict) -> ec.EllipticCurvePrivateKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or "d" not in jwk:
        raise ValueError("need an EC P-256 private JWK")
    d = int.from_bytes(b64u_dec(jwk["d"]), "big")
    return ec.derive_private_key(d, ec.SECP256R1())


def es256_sign_raw(jwk: dict, data: bytes) -> bytes:
    """ECDSA P-256 / SHA-256 signature in JOSE raw r||s form (64 bytes)."""
    der = private_key_from_jwk(jwk).sign(data, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def es256_sign_der(jwk: dict, data: bytes) -> bytes:
    return private_key_from_jwk(jwk).sign(data, ec.ECDSA(hashes.SHA256()))


def sign_compact(header: dict, claims: dict, *, key: dict | None, alg: str | None = None,
                 hmac_key: bytes | None = None, signature: str | None = None) -> str:
    """Produce a compact JWS. `alg` selects how the signature is computed (defaults to header alg).

    - "ES256": raw r||s ECDSA with `key`
    - "none": empty signature
    - "HS256": HMAC-SHA256 with `hmac_key`
    `signature` (base64url string) overrides whatever would be computed.
    """
    signing_input = f"{b64u_json(header)}.{b64u_json(claims)}"
    mode = alg if alg is not None else header.get("alg", "ES256")
    if signature is not None:
        sig = signature
    elif mode == "none":
        sig = ""
    elif mode == "HS256":
        sig = b64u(hmac.new(hmac_key or b"", signing_input.encode(), hashlib.sha256).digest())
    else:
        if key is None:
            raise ValueError("signing key required")
        sig = b64u(es256_sign_raw(key, signing_input.encode()))
    return f"{signing_input}.{sig}"


def ath_for(access_token: str) -> str:
    return b64u(hashlib.sha256(access_token.encode("ascii")).digest())
