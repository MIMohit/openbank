"""[W18 ablation copy: adds mint_bound() for +query/+digest.]
DPoP proof minting (RFC 9449) with full control over every header and claim.

`mint_proof` builds a well-formed proof by default; every field can be overridden,
dropped, or corrupted. `VARIANTS` names the malformed variants used by the verifier
tests and the mutator (mirrors the OIDF FAPI2 DPoP negative-test list).
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable

from . import keys as K
from .jose import ath_for, b64u, b64u_dec, public_jwk, sign_compact

_UNSET: Any = object()


def mint_proof(key: dict, htm: str, htu: str, access_token: str | None = None, *,
               iat: int | None = None, iat_offset: int = 0, jti: str | None = None,
               typ: Any = "dpop+jwt", alg: Any = "ES256", jwk: Any = _UNSET,
               ath: str | None = None, include_ath: bool = True,
               header_extra: dict | None = None, claims_extra: dict | None = None,
               header_drop=(), claims_drop=(), sign_key: dict | None = None,
               sign_alg: str | None = None, hmac_key: bytes | None = None,
               signature: str | None = None, corrupt_signature: bool = False) -> str:
    """Return a compact DPoP proof JWS.

    key          client private JWK (its public part goes in the `jwk` header by default)
    jwk          header jwk override (e.g. the full private JWK, or another client's key)
    typ/alg      header values; pass None to omit the member
    ath          explicit ath; by default computed from access_token if given
    sign_key     key actually used to sign (default `key`) -> "signed by different key"
    sign_alg     how to compute the signature ("ES256" | "none" | "HS256"); default = header alg
    hmac_key     HS256 key (default: JSON of the public jwk, the classic alg-confusion choice)
    signature    explicit base64url signature string
    corrupt_signature  flip one bit of an otherwise valid signature
    """
    header: dict[str, Any] = {}
    if typ is not None:
        header["typ"] = typ
    if alg is not None:
        header["alg"] = alg
    hdr_jwk = public_jwk(key) if jwk is _UNSET else jwk
    if hdr_jwk is not None:
        hdr_jwk = {k: v for k, v in hdr_jwk.items() if k != "kid"} if jwk is _UNSET else hdr_jwk
        header["jwk"] = hdr_jwk
    header.update(header_extra or {})
    for h in header_drop:
        header.pop(h, None)

    claims: dict[str, Any] = {
        "jti": jti or str(uuid.uuid4()),
        "htm": htm,
        "htu": htu,
        "iat": (int(time.time()) if iat is None else iat) + iat_offset,
    }
    if include_ath:
        if ath is not None:
            claims["ath"] = ath
        elif access_token is not None:
            claims["ath"] = ath_for(access_token)
    claims.update(claims_extra or {})
    for c in claims_drop:
        claims.pop(c, None)

    mode = sign_alg or (alg if alg in ("none", "HS256") else "ES256")
    if mode == "HS256" and hmac_key is None:
        hmac_key = json.dumps(public_jwk(key), separators=(",", ":")).encode()
    proof = sign_compact(header, claims, key=sign_key or key, alg=mode, hmac_key=hmac_key, signature=signature)
    if corrupt_signature:
        h, p, s = proof.split(".")
        raw = bytearray(b64u_dec(s))
        raw[len(raw) // 2] ^= 0x01
        proof = f"{h}.{p}.{b64u(bytes(raw))}"
    return proof


def decode_unverified(proof: str) -> tuple[dict, dict]:
    h, p, _ = proof.split(".")
    return json.loads(b64u_dec(h)), json.loads(b64u_dec(p))


# ---------------------------------------------------------------------------
# Named variants. Each maps to a function(ctx) -> kwargs for mint_proof, where ctx has
# key, other_key, htm, htu, at. Variants that are not single-proof shaped (no DPoP
# header, two DPoP headers, Bearer downgrade) are request-level and live in
# REQUEST_VARIANTS; the CLI and the tests handle them.
# ---------------------------------------------------------------------------
def _alt_method(m: str) -> str:
    return "PUT" if m.upper() != "PUT" else "POST"


VARIANTS: dict[str, Callable[[dict], dict]] = {
    "valid": lambda c: {},
    "missing_typ": lambda c: {"typ": None},
    "missing_alg": lambda c: {"alg": None, "sign_alg": "ES256"},
    "missing_jwk": lambda c: {"jwk": None},
    "missing_jti": lambda c: {"claims_drop": ["jti"]},
    "missing_htm": lambda c: {"claims_drop": ["htm"]},
    "missing_htu": lambda c: {"claims_drop": ["htu"]},
    "missing_iat": lambda c: {"claims_drop": ["iat"]},
    "missing_ath": lambda c: {"include_ath": False},
    "wrong_typ": lambda c: {"typ": "jwt"},
    "alg_none": lambda c: {"alg": "none"},
    "alg_hs256": lambda c: {"alg": "HS256"},
    "bad_signature": lambda c: {"corrupt_signature": True},
    "private_key_in_jwk": lambda c: {"jwk": dict(c["key"])},
    "wrong_htm": lambda c: {"htm": _alt_method(c["htm"])},
    "lowercase_htm": lambda c: {"htm": c["htm"].lower()},
    "wrong_htu": lambda c: {"htu": c["htu"] + "ohnonotagain"},
    "iat_future_1h": lambda c: {"iat_offset": 3600},
    "iat_past_1h": lambda c: {"iat_offset": -3600},
    "wrong_ath": lambda c: {"ath": ath_for((c["at"] or "") + "x")},
    "different_key": lambda c: {"key": c["other_key"]},       # proof key != token cnf.jkt
    "jwk_signature_mismatch": lambda c: {"sign_key": c["other_key"]},  # header jwk != signing key
    "extra_claims": lambda c: {"header_extra": {"x-extra": "1"}, "claims_extra": {"extra": "claim", "nonce_x": 1}},
    "htu_with_query": lambda c: {"htu": c["htu"] + "?foo=bar"},
    "htu_with_fragment": lambda c: {"htu": c["htu"] + "#frag"},
    "htu_upper_scheme_host": lambda c: {"htu": _upper_scheme_host(c["htu"])},
    "htu_default_port": lambda c: {"htu": _with_default_port(c["htu"])},
}

REQUEST_VARIANTS = ("no_dpop", "multiple_dpop", "bearer_downgrade", "reused_jti")


def _upper_scheme_host(u: str) -> str:
    scheme, rest = u.split("://", 1)
    host, sep, path = rest.partition("/")
    return f"{scheme.upper()}://{host.upper()}{sep}{path}"


def _with_default_port(u: str) -> str:
    scheme, rest = u.split("://", 1)
    host, sep, path = rest.partition("/")
    port = {"http": "80", "https": "443"}[scheme.lower()]
    return f"{scheme}://{host}:{port}{sep}{path}"


def mint_variant(name: str, *, key: dict, other_key: dict, htm: str, htu: str, at: str | None, **kw) -> str:
    ctx = {"key": key, "other_key": other_key, "htm": htm, "htu": htu, "at": at}
    args = {"key": key, "htm": htm, "htu": htu, "access_token": at}
    args.update(VARIANTS[name](ctx))
    args.update(kw)
    k = args.pop("key")
    return mint_proof(k, args.pop("htm"), args.pop("htu"), args.pop("access_token"), **args)


def headers_for(client: str = "alice", htm: str = "GET", htu: str = "http://api.bench.test/api/v1/me", *,
                variant: str = "valid", access_token: str | None = None, other_client: str | None = None,
                **proof_kw) -> dict:
    """Mint a token (unless given) and a proof variant; return the request headers as a dict.

    Request-level variants: no_dpop (omit DPoP), multiple_dpop (DPoP is a list of 2 proofs),
    bearer_downgrade (Authorization: Bearer, no DPoP). reused_jti is just a fixed jti; the
    caller sends it twice.
    """
    from .tokens import mint_access_token

    at = access_token or mint_access_token(client)
    key = K.client_key(client)
    other = K.client_key(other_client or ("bob" if client != "bob" else "alice"))
    if variant == "bearer_downgrade":
        return {"Authorization": f"Bearer {at}"}
    if variant in ("no_dpop",):
        return {"Authorization": f"DPoP {at}"}
    pname = "valid" if variant in REQUEST_VARIANTS else variant
    proof = mint_variant(pname, key=key, other_key=other, htm=htm, htu=htu, at=at, **proof_kw)
    out: dict[str, Any] = {"Authorization": f"DPoP {at}", "DPoP": proof}
    if variant == "multiple_dpop":
        out["DPoP"] = [proof, mint_variant("valid", key=key, other_key=other, htm=htm, htu=htu, at=at)]
    return out


# ---------------------------------------------------------------------------
# W18 ablation (A1): proofs for the +query / +digest binding variants.
# ---------------------------------------------------------------------------
def content_digest(body: bytes) -> str:
    """RFC 9530 Content-Digest field value (single sha-256 member) of the request content."""
    import base64
    import hashlib
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body or b"").digest()).decode() + ":"


def mint_bound(client: str, htm: str, htu: str, *, query: str | None = None, body: bytes | None = None,
               bind_query: bool = False, bind_digest: bool = False,
               access_token: str | None = None) -> tuple[str, str, str, str | None]:
    """Mint (Authorization value, proof, jti, content_digest_or_None) for one base request.

    bind_query   htu claim = htu + "?" + query (query as sent by the legitimate client, verbatim)
    bind_digest  proof carries claim cdig = Content-Digest(body); the caller must send that value in a
                 Content-Digest header (returned as the 4th element)
    """
    from .tokens import mint_access_token
    at = access_token or mint_access_token(client)
    key = K.client_key(client)
    u = htu + ("?" + query if (bind_query and query) else "")
    extra = {}
    cd = None
    if bind_digest:
        cd = content_digest(body or b"")
        extra["cdig"] = cd
    proof = mint_proof(key, htm, u, at, claims_extra=extra or None)
    _, claims = decode_unverified(proof)
    return f"DPoP {at}", proof, claims["jti"], cd
