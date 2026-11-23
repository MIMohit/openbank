"""draft-cavage-http-signatures-12 signer/verifier for the E6 signature arm.

Signature header: keyId="..",algorithm="hs2019",headers="h1 h2 ..",signature="<base64>".
Signing string: one line per listed header, "name: value"; "(request-target)" is
"<lower method> <path?query>"; "(created)" is the created timestamp.
Signature: ECDSA P-256 SHA-256 with the client key, DER-encoded (the encoding used by
the common Java/Node cavage libraries; the draft does not fix it for hs2019).

Profiles (PROFILES):
  berlin-group : digest x-request-id date          (Berlin Group NextGenPSD2 style; no request target)
  with-target  : (request-target) host date digest (binds method + path + query + body)
  date-only    : date
"""
from __future__ import annotations

import base64
import hashlib
import re
from email.utils import formatdate
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from .jose import b64u_dec, es256_sign_der, thumbprint

PROFILES: dict[str, tuple[str, ...]] = {
    "berlin-group": ("digest", "x-request-id", "date"),
    "with-target": ("(request-target)", "host", "date", "digest"),
    "date-only": ("date",),
}


def digest_header(body: bytes) -> str:
    """RFC 3230 Digest header, SHA-256."""
    return "SHA-256=" + base64.b64encode(hashlib.sha256(body).digest()).decode()


def _hdr(headers, name: str) -> str | None:
    vals = [v.strip() for k, v in headers if k.lower() == name]
    return ", ".join(vals) if vals else None


def signing_string(method: str, target: str, headers, covered: Iterable[str], created: int | None = None) -> bytes:
    lines = []
    for h in covered:
        if h == "(request-target)":
            lines.append(f"(request-target): {method.lower()} {target}")
        elif h == "(created)":
            lines.append(f"(created): {created}")
        else:
            v = _hdr(headers, h)
            if v is None:
                raise KeyError(f"missing covered header {h}")
            lines.append(f"{h}: {v}")
    return "\n".join(lines).encode()


def sign_request(method: str, target: str, headers: list[tuple[str, str]], body: bytes, key: dict, *,
                 covered: Iterable[str] | str = "berlin-group", key_id: str | None = None,
                 request_id: str | None = None) -> list[tuple[str, str]]:
    """Return headers to ADD (Digest/Date/X-Request-ID when covered and absent, then Signature).
    `target` is the request-target as sent (path?query)."""
    cov = tuple(PROFILES[covered] if isinstance(covered, str) else covered)
    hdrs = list(headers)
    add: list[tuple[str, str]] = []
    if "digest" in cov and _hdr(hdrs, "digest") is None:
        add.append(("Digest", digest_header(body)))
    if "date" in cov and _hdr(hdrs, "date") is None:
        add.append(("Date", formatdate(usegmt=True)))
    if "x-request-id" in cov and _hdr(hdrs, "x-request-id") is None:
        import uuid
        add.append(("X-Request-ID", request_id or str(uuid.uuid4())))
    hdrs += add
    sig = base64.b64encode(es256_sign_der(key, signing_string(method, target, hdrs, cov))).decode()
    kid = key_id or thumbprint(key)
    add.append(("Signature", f'keyId="{kid}",algorithm="hs2019",headers="{" ".join(cov)}",signature="{sig}"'))
    return add


def verify_request(method: str, target: str, headers, body: bytes, pub: dict, *,
                   required: Iterable[str] = ()) -> tuple[bool, str]:
    sh = _hdr(headers, "signature")
    if not sh:
        return False, "missing_signature"
    params = dict(re.findall(r'(\w+)="([^"]*)"', sh))
    cov = params.get("headers", "date").split()
    for r in required:
        if r not in cov:
            return False, f"component_not_covered:{r}"
    if "digest" in cov and _hdr(headers, "digest") != digest_header(body):
        return False, "digest_mismatch"
    try:
        ss = signing_string(method, target, headers, cov)
    except KeyError as e:
        return False, f"base_error:{e}"
    x = int.from_bytes(b64u_dec(pub["x"]), "big")
    y = int.from_bytes(b64u_dec(pub["y"]), "big")
    pk = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    try:
        pk.verify(base64.b64decode(params.get("signature", "")), ss, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError):
        return False, "bad_signature"
    return True, "ok"
