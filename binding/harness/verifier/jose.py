"""Strict JOSE primitives for the verifier (cryptography only)."""
from __future__ import annotations

import base64
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

_B64U = re.compile(r"^[A-Za-z0-9_-]*$")

# alg -> (kty, crv or None, hash, raw signature length for EC)
ASYM_ALGS = {
    "ES256": ("EC", "P-256", hashes.SHA256, 64),
    "ES384": ("EC", "P-384", hashes.SHA384, 96),
    "ES512": ("EC", "P-521", hashes.SHA512, 132),
    "RS256": ("RSA", None, hashes.SHA256, None),
    "PS256": ("RSA", None, hashes.SHA256, None),
}
_CURVES = {"P-256": ec.SECP256R1, "P-384": ec.SECP384R1, "P-521": ec.SECP521R1}
PRIVATE_MEMBERS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")


class JoseError(ValueError):
    pass


def b64u_decode(s: str) -> bytes:
    """Strict base64url without padding (RFC 7515 section 2)."""
    if not isinstance(s, str) or not _B64U.match(s) or len(s) % 4 == 1:
        raise JoseError("bad base64url")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def parse_compact(token: str) -> tuple[dict, dict, bytes, bytes]:
    """Return (header, payload, signing_input, signature). Raises JoseError if malformed."""
    if not isinstance(token, str):
        raise JoseError("not a string")
    parts = token.split(".")
    if len(parts) != 3:
        raise JoseError("not three parts")
    try:
        header = json.loads(b64u_decode(parts[0]))
        payload = json.loads(b64u_decode(parts[1]))
    except (JoseError, ValueError, UnicodeDecodeError) as e:
        raise JoseError(f"undecodable: {e}") from None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JoseError("header/payload not JSON objects")
    sig = b64u_decode(parts[2])
    return header, payload, f"{parts[0]}.{parts[1]}".encode("ascii"), sig


def unverified_payload(token: str | None) -> dict | None:
    if not token:
        return None
    try:
        parts = token.split(".")
        p = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        return p if isinstance(p, dict) else None
    except Exception:
        return None


def thumbprint(jwk: dict) -> str:
    """RFC 7638 SHA-256 thumbprint."""
    kty = jwk.get("kty")
    if kty == "EC":
        req = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "RSA":
        req = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    elif kty == "OKP":
        req = {"crv": jwk["crv"], "kty": "OKP", "x": jwk["x"]}
    else:
        raise JoseError("unsupported kty")
    return b64u(hashlib.sha256(json.dumps(req, separators=(",", ":"), sort_keys=True).encode()).digest())


def public_key(jwk: dict, alg: str):
    """Build a public key for `alg` from a JWK; raises JoseError on mismatch/invalid key."""
    if alg not in ASYM_ALGS:
        raise JoseError("unsupported alg")
    kty, crv, _, _ = ASYM_ALGS[alg]
    if not isinstance(jwk, dict) or jwk.get("kty") != kty:
        raise JoseError("kty does not match alg")
    try:
        if kty == "EC":
            if jwk.get("crv") != crv:
                raise JoseError("crv does not match alg")
            x = int.from_bytes(b64u_decode(jwk["x"]), "big")
            y = int.from_bytes(b64u_decode(jwk["y"]), "big")
            return ec.EllipticCurvePublicNumbers(x, y, _CURVES[crv]()).public_key()  # validates point
        n = int.from_bytes(b64u_decode(jwk["n"]), "big")
        e = int.from_bytes(b64u_decode(jwk["e"]), "big")
        if n.bit_length() < 2048:
            raise JoseError("RSA key too small")
        return rsa.RSAPublicNumbers(e, n).public_key()
    except JoseError:
        raise
    except Exception as ex:  # KeyError, ValueError (point not on curve) ...
        raise JoseError(f"invalid jwk: {ex}") from None


def verify_signature(key, alg: str, signing_input: bytes, sig: bytes) -> bool:
    kty, _, h, siglen = ASYM_ALGS[alg]
    try:
        if kty == "EC":
            if len(sig) != siglen:
                return False
            half = siglen // 2
            der = encode_dss_signature(int.from_bytes(sig[:half], "big"), int.from_bytes(sig[half:], "big"))
            key.verify(der, signing_input, ec.ECDSA(h()))
        elif alg == "RS256":
            key.verify(sig, signing_input, padding.PKCS1v15(), h())
        else:
            key.verify(sig, signing_input, padding.PSS(mgf=padding.MGF1(h()), salt_length=h.digest_size), h())
        return True
    except (InvalidSignature, ValueError):
        return False


def sha256_b64u(s: str) -> str:
    return b64u(hashlib.sha256(s.encode("ascii")).digest())
