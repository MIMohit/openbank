"""RFC 9421 HTTP Message Signatures: signer and verifier for the E6 signature arm.

Algorithm: ecdsa-p256-sha256 (RFC 9421 section 3.3.4, raw r||s, 64 bytes) with the client keys.
Covered components are selectable; named profiles in COVERAGE (the default "full" covers what
the executor dispatches on: method, full target URI incl. query, and the body via Content-Digest).
Implemented derived components (section 2.2): @method @target-uri @authority @scheme
@request-target @path @query. Header fields: lower-cased name, values trimmed and joined ", ".
Not implemented: ;sf/;key/;bs/;req/;tr parameters, @query-param, @status.
"""
from __future__ import annotations

import base64
import hashlib
import re
import time
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .jose import b64u_dec, es256_sign_raw, thumbprint

ALG = "ecdsa-p256-sha256"

COVERAGE: dict[str, tuple[str, ...]] = {
    "full": ("@method", "@target-uri", "content-digest"),          # recommended: binds what executes
    "method-path-query": ("@method", "@path", "@query", "content-digest"),
    "method-target": ("@method", "@target-uri"),                    # no body
    "target-only": ("@target-uri",),                                # no method (replay across methods)
    "path-only": ("@path",),                                        # no method, no query
    "authority-path": ("@authority", "@path"),
    "digest-only": ("content-digest",),                             # cavage-like minimal
}

_URL = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://([^/?#]*)([^?#]*)(\?[^#]*)?")
_DEFAULT_PORT = {"http": "80", "https": "443"}


def content_digest(body: bytes) -> str:
    """RFC 9530 Content-Digest (sha-256)."""
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


def _split(url: str):
    m = _URL.match(url)
    if not m:
        raise ValueError(f"not an absolute URL: {url!r}")
    return m.group(1), m.group(2), m.group(3) or "", m.group(4) or ""


def _hdr(headers: Iterable[tuple[str, str]], name: str) -> str | None:
    vals = [v.strip() for k, v in headers if k.lower() == name]
    return ", ".join(vals) if vals else None


def component_value(name: str, method: str, url: str, headers) -> str:
    scheme, authority, path, query = _split(url)
    if name == "@method":
        return method
    if name == "@target-uri":
        return url
    if name == "@authority":
        host, _, port = authority.lower().rpartition(":") if ":" in authority else (authority.lower(), "", "")
        if port and port == _DEFAULT_PORT.get(scheme.lower()):
            return host
        return authority.lower()
    if name == "@scheme":
        return scheme.lower()
    if name == "@request-target":
        return (path or "/") + query
    if name == "@path":
        return path or "/"
    if name == "@query":
        return query if query else "?"
    if name.startswith("@"):
        raise ValueError(f"unsupported derived component {name}")
    v = _hdr(headers, name.lower())
    if v is None:
        raise KeyError(f"missing covered header {name}")
    return v


def signature_params(components, created: int, keyid: str, alg: str = ALG, nonce: str | None = None,
                     tag: str | None = None, expires: int | None = None) -> str:
    inner = " ".join(f'"{c}"' for c in components)
    s = f"({inner});created={created}"
    if expires is not None:
        s += f";expires={expires}"
    s += f';keyid="{keyid}";alg="{alg}"'
    if nonce:
        s += f';nonce="{nonce}"'
    if tag:
        s += f';tag="{tag}"'
    return s


def signature_base(method: str, url: str, headers, components, params: str) -> bytes:
    lines = [f'"{c}": {component_value(c, method, url, headers)}' for c in components]
    lines.append(f'"@signature-params": {params}')
    return "\n".join(lines).encode()


def sign_request(method: str, url: str, headers: list[tuple[str, str]], body: bytes, key: dict, *,
                 components: Iterable[str] | str = "full", label: str = "sig1", created: int | None = None,
                 keyid: str | None = None, nonce: str | None = None) -> list[tuple[str, str]]:
    """Return the headers to ADD: Content-Digest (if covered and absent), Signature-Input, Signature."""
    comps = tuple(COVERAGE[components] if isinstance(components, str) else components)
    hdrs = list(headers)
    add: list[tuple[str, str]] = []
    if "content-digest" in comps and _hdr(hdrs, "content-digest") is None:
        add.append(("Content-Digest", content_digest(body)))
        hdrs += add
    params = signature_params(comps, int(time.time()) if created is None else created,
                              keyid or thumbprint(key), nonce=nonce)
    base = signature_base(method, url, hdrs, comps, params)
    sig = base64.b64encode(es256_sign_raw(key, base)).decode()
    add += [("Signature-Input", f"{label}={params}"), ("Signature", f"{label}=:{sig}:")]
    return add


_SI = re.compile(r'^\s*([a-z*][a-z0-9_.*-]*)=\(([^)]*)\)(.*)$')


def verify_request(method: str, url: str, headers, body: bytes, pub: dict, *, label: str = "sig1",
                   required: Iterable[str] = (), max_age: int | None = 300) -> tuple[bool, str]:
    """Verify one signature. `required` lists components that must be covered (verifier policy)."""
    si, sg = _hdr(headers, "signature-input"), _hdr(headers, "signature")
    if not si or not sg:
        return False, "missing_signature"
    entry = next((e for e in si.split(", ") if e.startswith(label + "=")), None)
    m = _SI.match(entry or "")
    if not m:
        return False, "bad_signature_input"
    comps = re.findall(r'"([^"]+)"', m.group(2))
    params = f"({m.group(2)}){m.group(3)}"
    for r in required:
        if r not in comps:
            return False, f"component_not_covered:{r}"
    if "alg=" in m.group(3) and f'alg="{ALG}"' not in m.group(3):
        return False, "alg_unsupported"
    cm = re.search(r";created=(\d+)", m.group(3))
    if max_age is not None and (not cm or abs(time.time() - int(cm.group(1))) > max_age):
        return False, "stale"
    if "content-digest" in comps and _hdr(headers, "content-digest") != content_digest(body):
        return False, "content_digest_mismatch"
    sm = re.search(re.escape(label) + r"=:([A-Za-z0-9+/=]+):", sg)
    if not sm:
        return False, "bad_signature_header"
    try:
        base = signature_base(method, url, headers, comps, params)
    except (KeyError, ValueError) as e:
        return False, f"base_error:{e}"
    raw = base64.b64decode(sm.group(1))
    if len(raw) != 64:
        return False, "bad_signature_length"
    x = int.from_bytes(b64u_dec(pub["x"]), "big")
    y = int.from_bytes(b64u_dec(pub["y"]), "big")
    pk = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    try:
        pk.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
                  base, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False, "bad_signature"
    return True, "ok"
