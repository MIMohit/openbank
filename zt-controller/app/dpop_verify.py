"""
Stage 2: DPoP proof verification (RFC 9449).

Steps:
  1. Parse DPoP JWT (header.payload.signature)
  2. Verify typ=dpop+jwt
  3. Extract embedded public key (no private key allowed)
  4. Verify JWS signature using the embedded EC public key
  5. Confirm JWK thumbprint equals token cnf.jkt
  6. Check htm / htu match the request
  7. Enforce iat within dpop_skew window
  8. Reject duplicate jti via replay cache (TTL = skew window)
  9. Verify ath (access-token hash) binding

Raises HTTPException(401) on any failure.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
from typing import Optional

from cachetools import TTLCache
from fastapi import HTTPException, status

from app import config

logger = logging.getLogger(__name__)

# In-memory replay cache for jti values
_jti_cache: TTLCache = TTLCache(
    maxsize=100_000,
    ttl=config.JTI_CACHE_TTL_SECONDS,
)


def _b64url_decode(s: str) -> bytes:
    """Decode a base64url string (with or without padding) to bytes."""
    # Add padding
    s = s + "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _jwk_thumbprint_sha256(jwk_dict: dict) -> str:
    """Compute RFC 7638 JWK SHA-256 thumbprint."""
    kty = jwk_dict.get("kty")
    if kty == "EC":
        required = {
            "crv": jwk_dict["crv"],
            "kty": "EC",
            "x": jwk_dict["x"],
            "y": jwk_dict["y"],
        }
    elif kty == "RSA":
        required = {"e": jwk_dict["e"], "kty": "RSA", "n": jwk_dict["n"]}
    else:
        raise ValueError(f"Unsupported key type: {kty}")
    canonical = json.dumps(required, separators=(",", ":"), sort_keys=True).encode()
    digest = hashlib.sha256(canonical).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _verify_ec_sig(public_jwk: dict, signing_input: bytes, sig_bytes: bytes) -> bool:
    """Verify an ES256 signature using the cryptography library."""
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicKey, SECP256R1, ECDSA,
    )
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicNumbers,
    )

    if len(sig_bytes) != 64:
        return False

    x_int = int.from_bytes(_b64url_decode(public_jwk["x"]), "big")
    y_int = int.from_bytes(_b64url_decode(public_jwk["y"]), "big")
    pub_numbers = EllipticCurvePublicNumbers(x=x_int, y=y_int, curve=SECP256R1())
    pub_key = pub_numbers.public_key()

    r = int.from_bytes(sig_bytes[:32], "big")
    s = int.from_bytes(sig_bytes[32:], "big")
    der_sig = encode_dss_signature(r, s)

    try:
        pub_key.verify(der_sig, signing_input, ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def _access_token_hash(raw_at: str) -> str:
    digest = hashlib.sha256(raw_at.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def verify_dpop_proof(
    dpop_header: str,
    method: str,
    url: str,
    raw_access_token: str,
    cnf_jkt: str,
) -> dict:
    """
    Verify a DPoP proof JWT.  Returns the decoded payload on success.
    Raises HTTPException(401) on any failure.
    """
    if not dpop_header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Missing DPoP proof header")

    parts = dpop_header.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Malformed DPoP proof (expected 3 parts)")

    # 1. Decode header
    try:
        dpop_hdr = json.loads(_b64url_decode(parts[0]))
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Cannot decode DPoP header")

    # 2. typ check
    if dpop_hdr.get("typ") != "dpop+jwt":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="DPoP proof typ must be dpop+jwt")

    # 3. Extract embedded public key; reject private key material
    jwk_pub = dpop_hdr.get("jwk")
    if not jwk_pub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="DPoP proof missing embedded jwk")
    if "d" in jwk_pub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="DPoP proof must not contain private key")

    # 4. Verify JWS signature
    alg = dpop_hdr.get("alg", "ES256")
    if alg != "ES256":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"Unsupported DPoP alg: {alg}")

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        sig_bytes = _b64url_decode(parts[2])
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Cannot decode DPoP signature")

    if not _verify_ec_sig(jwk_pub, signing_input, sig_bytes):
        logger.warning({"event": "dpop_sig_invalid"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="DPoP proof signature invalid")

    # 5. Decode payload
    try:
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Cannot decode DPoP payload")

    # 6. cnf.jkt match — the sender-constraining check itself.  Gated by
    # CHECK_DEVICE_BINDING so the §7.4 "P − device-binding" ablation can
    # measure a controller that verifies the proof's signature and freshness
    # but no longer binds it to the token's key.  It is always on in B1 and P.
    computed_jkt = _jwk_thumbprint_sha256(jwk_pub)
    if computed_jkt != cnf_jkt and config.CHECK_DEVICE_BINDING:
        logger.warning({"event": "dpop_jkt_mismatch",
                        "computed": computed_jkt, "expected": cnf_jkt})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="DPoP cnf.jkt binding mismatch")

    # 7. htm / htu
    if payload.get("htm", "").upper() != method.upper():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"DPoP htm mismatch: expected {method}")
    if payload.get("htu", "").rstrip("/") != url.rstrip("/"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"DPoP htu mismatch: expected {url}")

    # 8. iat skew
    iat = payload.get("iat")
    if iat is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="DPoP proof missing iat")
    skew = config.DPOP_SKEW_SECONDS
    if abs(time.time() - iat) > skew:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"DPoP proof iat outside skew window (±{skew}s)")

    # 9. jti replay
    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="DPoP proof missing jti")
    if jti in _jti_cache:
        logger.warning({"event": "dpop_jti_replay", "jti": jti})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="DPoP proof jti already used (replay detected)")
    _jti_cache[jti] = True

    # 10. ath binding
    expected_ath = _access_token_hash(raw_access_token)
    if payload.get("ath") != expected_ath:
        logger.warning({"event": "dpop_ath_mismatch"})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="DPoP ath does not match access token")

    payload["_jkt"] = computed_jkt
    return payload


def reset() -> None:
    """Clear the jti replay cache (harness control plane only)."""
    _jti_cache.clear()
