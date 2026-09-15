from __future__ import annotations
"""
Device simulator — EC keypair, device enrollment, DPoP proof signing.

A Device represents one enrolled client.  It:
  - Generates a P-256 EC keypair on construction
  - Computes its own JWK thumbprint (used as cnf.jkt)
  - Signs a fresh DPoP proof per request (htm, htu, iat, jti, ath)
  - Emits stable context metadata (ip, geo, device_fp) for telemetry

Context can be selectively perturbed to simulate attacks.
"""
import base64
import hashlib
import json
import time
import uuid
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    generate_private_key,
    derive_private_key,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# P-256 curve order
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign_es256(private_key: EllipticCurvePrivateKey, message: bytes) -> bytes:
    sig_der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(sig_der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


class Device:
    """Represents a single enrolled device with its EC keypair."""

    def __init__(
        self,
        device_id: Optional[str] = None,
        geo: str = "AU",
        source_ip: str = "10.0.0.1",
        seed: Optional[int] = None,
    ):
        self.geo = geo
        self.source_ip = source_ip

        if seed is not None:
            # Deterministic key and device_id from seed alone
            key_material = hashlib.sha256(f"device-key-{seed}".encode()).digest()
            priv_int = int.from_bytes(key_material, "big") % _P256_ORDER or 1
            self._private_key = derive_private_key(priv_int, SECP256R1())
            self.device_id = device_id or f"d_seed{seed}"
        else:
            self._private_key = generate_private_key(SECP256R1())
            self.device_id = device_id or f"d_{uuid.uuid4().hex[:8]}"

        self._public_key: EllipticCurvePublicKey = self._private_key.public_key()
        self._jwk_public = self._build_public_jwk()
        self._jkt = self._compute_thumbprint()
        # Stable device fingerprint token (hash of public key)
        self.device_fp = hashlib.sha256(
            json.dumps(self._jwk_public, sort_keys=True).encode()
        ).hexdigest()[:16]

    def _build_public_jwk(self) -> dict:
        pub = self._public_key
        pub_bytes = pub.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        x = _b64url(pub_bytes[1:33])
        y = _b64url(pub_bytes[33:65])
        return {"kty": "EC", "crv": "P-256", "x": x, "y": y}

    def _compute_thumbprint(self) -> str:
        jwk = self._jwk_public
        required = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
        canonical = json.dumps(required, separators=(",", ":"), sort_keys=True).encode()
        digest = hashlib.sha256(canonical).digest()
        return _b64url(digest)

    @property
    def jwk_public(self) -> dict:
        return self._jwk_public.copy()

    @property
    def jkt(self) -> str:
        """JWK SHA-256 thumbprint — used as cnf.jkt in access tokens."""
        return self._jkt

    def sign_dpop_proof(
        self,
        method: str,
        url: str,
        access_token: Optional[str] = None,
        override_jti: Optional[str] = None,
        override_iat: Optional[float] = None,
    ) -> str:
        """
        Produce a fresh DPoP proof JWT (RFC 9449) for the given request.
        """
        header = {
            "typ": "dpop+jwt",
            "alg": "ES256",
            "jwk": self._jwk_public,
        }
        payload: dict = {
            "jti": override_jti or str(uuid.uuid4()),
            "htm": method.upper(),
            "htu": url,
            "iat": int(override_iat if override_iat is not None else time.time()),
        }
        if access_token:
            ath_bytes = hashlib.sha256(access_token.encode()).digest()
            payload["ath"] = _b64url(ath_bytes)

        header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode())
        signing_input = f"{header_b64}.{payload_b64}".encode()
        sig_bytes = _sign_es256(self._private_key, signing_input)
        sig_b64 = _b64url(sig_bytes)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def context_headers(
        self,
        geo: Optional[str] = None,
        source_ip: Optional[str] = None,
        device_fp: Optional[str] = None,
    ) -> dict:
        """HTTP headers carrying context metadata for telemetry."""
        return {
            "x-device-id": self.device_id,
            "x-device-fp": device_fp or self.device_fp,
            "x-geo": geo or self.geo,
            "x-forwarded-for": source_ip or self.source_ip,
            "x-session-id": self.device_id,
        }
