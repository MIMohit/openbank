"""[W18 ablation copy: BIND_CLAIMS / QUERY_CANON, see bind.py]
Reference DPoP verifier core: RFC 9449 section 4.3 proof checks + section 7 resource-server checks.

    verify(view, headers, config, now=None) -> Decision

`view` is the verifier's view of the client request (method, URI, host, proto), supplied by an
adapter. `headers` are the request headers that reach the verifier (a list of (name, value)
pairs, or a mapping whose values may be lists). Every check maps to one `reason` code (see
CHECKS). Order: Authorization scheme -> DPoP header count -> proof syntax/header/signature ->
proof claims (htm, htu, iat) -> access token (signature, typ, iss, aud, exp, nbf) -> ath ->
cnf.jkt -> jti replay. The jti is only recorded when the request would otherwise be allowed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from . import bind, canon
from .jose import (ASYM_ALGS, PRIVATE_MEMBERS, JoseError, b64u, parse_compact, public_key,
                   sha256_b64u, thumbprint, unverified_payload, verify_signature)

INVALID_PROOF = "invalid_dpop_proof"
INVALID_TOKEN = "invalid_token"

# reason code -> WWW-Authenticate error
CHECKS: dict[str, str] = {
    "view_missing": INVALID_PROOF, "view_invalid": INVALID_PROOF,
    "auth_missing": INVALID_TOKEN, "auth_multiple": INVALID_TOKEN, "auth_malformed": INVALID_TOKEN,
    "bearer_downgrade": INVALID_TOKEN, "auth_scheme_unsupported": INVALID_TOKEN,
    "dpop_missing": INVALID_PROOF, "dpop_multiple": INVALID_PROOF, "dpop_malformed": INVALID_PROOF,
    "missing_typ": INVALID_PROOF, "missing_alg": INVALID_PROOF, "missing_jwk": INVALID_PROOF,
    "wrong_typ": INVALID_PROOF, "alg_none": INVALID_PROOF, "alg_symmetric": INVALID_PROOF,
    "alg_unsupported": INVALID_PROOF, "jwk_private": INVALID_PROOF, "jwk_invalid": INVALID_PROOF,
    "bad_signature": INVALID_PROOF,
    "missing_jti": INVALID_PROOF, "missing_htm": INVALID_PROOF, "missing_htu": INVALID_PROOF,
    "missing_iat": INVALID_PROOF, "missing_ath": INVALID_PROOF,
    "htm_mismatch": INVALID_PROOF, "htu_mismatch": INVALID_PROOF, "htu_invalid": INVALID_PROOF,
    "iat_skew": INVALID_PROOF, "jti_replay": INVALID_PROOF, "ath_mismatch": INVALID_PROOF,
    "token_malformed": INVALID_TOKEN, "token_typ": INVALID_TOKEN, "token_alg": INVALID_TOKEN,
    "token_signature": INVALID_TOKEN, "token_iss": INVALID_TOKEN, "token_aud": INVALID_TOKEN,
    "token_expired": INVALID_TOKEN, "token_nbf": INVALID_TOKEN, "token_no_cnf": INVALID_TOKEN,
    "jkt_mismatch": INVALID_TOKEN,
}

_AUTH = re.compile(r"^([A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*) +([A-Za-z0-9._~+/-]+=*)\s*$")
_TCHAR_METHOD = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


# --------------------------------------------------------------------------- data types
@dataclass
class View:
    method: str | None
    uri: str | None            # origin-form "/p?q" or absolute-form "http://h/p?q"
    host: str | None
    proto: str = "http"

    def url(self) -> str:
        u = self.uri or ""
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", u):
            return u
        return f"{(self.proto or 'http').lower()}://{self.host or ''}{u}"


class JtiCache:
    """Thread-safe in-memory TTL set."""

    def __init__(self, ttl: float, maxsize: int = 1_000_000):
        self.ttl, self.maxsize = ttl, maxsize
        self._d: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def seen(self, key: str, now: float) -> bool:
        with self._lock:
            self._expire(now)
            return key in self._d

    def add(self, key: str, now: float) -> bool:
        """Insert; return False if already present (replay)."""
        with self._lock:
            self._expire(now)
            if key in self._d:
                return False
            self._d[key] = now + self.ttl
            while len(self._d) > self.maxsize:
                self._d.popitem(last=False)
            return True

    def _expire(self, now: float) -> None:
        while self._d:
            k, exp = next(iter(self._d.items()))
            if exp > now:
                break
            self._d.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._d.clear()


@dataclass
class Config:
    as_pub_jwk: dict
    canon: str = "rfc3986"
    jti_cache: bool = True
    iat_window: int = 60
    view_mac: bool = False
    view_mac_key: bytes = b""
    iss: str = "https://as.bench.test"
    aud: str = "https://api.bench.test"
    allowed_algs: tuple[str, ...] = ("ES256", "ES384", "ES512", "RS256", "PS256")
    token_leeway: int = 0
    cache: JtiCache | None = None
    bind_claims: frozenset = frozenset()     # W18 ablation, see bind.py
    query_canon: str = "rfc3986"

    def __post_init__(self):
        if self.canon not in canon.MODES:
            raise ValueError(f"HTU_CANON must be one of {canon.MODES}")
        if self.view_mac and not self.view_mac_key:
            raise ValueError("VIEW_MAC=on requires VIEW_MAC_KEY")
        if self.query_canon not in bind.QUERY_MODES:
            raise ValueError(f"QUERY_CANON must be one of {bind.QUERY_MODES}")
        if self.cache is None:
            self.cache = JtiCache(ttl=2 * self.iat_window + 5)

    @classmethod
    def from_env(cls, env: Mapping[str, str] = os.environ) -> "Config":
        path = env.get("AS_PUB_JWK", str(Path(__file__).resolve().parent.parent / "keys" / "as_pub.jwk"))
        return cls(
            as_pub_jwk=json.loads(Path(path).read_text()),
            canon=env.get("HTU_CANON", "rfc3986"),
            jti_cache=env.get("JTI_CACHE", "on").lower() != "off",
            iat_window=int(env.get("IAT_WINDOW", "60")),
            view_mac=env.get("VIEW_MAC", "off").lower() == "on",
            view_mac_key=env.get("VIEW_MAC_KEY", "").encode(),
            iss=env.get("EXPECTED_ISS", "https://as.bench.test"),
            aud=env.get("EXPECTED_AUD", "https://api.bench.test"),
            bind_claims=bind.parse(env.get("BIND_CLAIMS", "full")),
            query_canon=env.get("QUERY_CANON", "rfc3986"),
        )


@dataclass
class Decision:
    allow: bool
    reason: str
    error: str | None = None
    sub: str | None = None
    jkt: str | None = None
    jti: str | None = None          # proof jti (unverified if the proof failed to parse/verify)
    htm: str | None = None
    htu: str | None = None
    view_url: str | None = None
    canon_htu: str | None = None
    canon_view: str | None = None
    response_headers: dict[str, str] = field(default_factory=dict)

    @property
    def status(self) -> int:
        return 200 if self.allow else 401

    def www_authenticate(self) -> str | None:
        if self.allow:
            return None
        return f'DPoP error="{self.error or INVALID_TOKEN}", algs="ES256 ES384 ES512 RS256 PS256"'


# --------------------------------------------------------------------------- helpers
def header_values(headers: Any, name: str) -> list[str]:
    name = name.lower()
    if isinstance(headers, Mapping):
        out = []
        for k, v in headers.items():
            if k.lower() == name:
                out += list(v) if isinstance(v, (list, tuple)) else [v]
        return out
    if hasattr(headers, "get_all"):  # email.message.Message (http.server)
        return list(headers.get_all(name) or [])
    return [v for k, v in headers if k.lower() == name]


def view_mac(key: bytes, jti: str, method: str, uri: str, jkt: str) -> str:
    """CONTRACT section 8. canon(view_uri without query) = RFC 3986-normalised path only."""
    msg = "\n".join([jti, method.upper(), canon.canon_path(uri), jkt]).encode()
    return "v1;" + b64u(hmac.new(key, msg, hashlib.sha256).digest())


def _deny(reason: str, **kw) -> Decision:
    return Decision(False, reason, CHECKS.get(reason, INVALID_PROOF), **kw)


def _reason(d: Decision, reason: str) -> Decision:
    d.reason = reason
    return d


# --------------------------------------------------------------------------- verify
def verify(view: View, headers: Any, config: Config, now: float | None = None) -> Decision:
    now = time.time() if now is None else now
    dpops = header_values(headers, "dpop")
    raw_jti = None
    if len(dpops) == 1:
        p = unverified_payload(dpops[0].strip())
        raw_jti = p.get("jti") if p and isinstance(p.get("jti"), str) else None
    base = {"jti": raw_jti}

    # --- view sanity (fail closed if the adapter could not reconstruct the view)
    if not view.method or not view.uri or not (view.host or view.uri.find("://") > 0):
        return _deny("view_missing", **base)
    vurl = view.url()
    base["view_url"] = vurl

    # --- section 7.1: Authorization header, DPoP scheme, no Bearer downgrade
    auths = header_values(headers, "authorization")
    if not auths:
        return _deny("auth_missing", **base)
    if len(auths) > 1:
        return _deny("auth_multiple", **base)
    m = _AUTH.match(auths[0].strip())
    if not m:
        return _deny("auth_malformed", **base)
    scheme, at = m.group(1), m.group(2)
    if scheme.lower() == "bearer":
        return _deny("bearer_downgrade", **base)
    if scheme.lower() != "dpop":
        return _deny("auth_scheme_unsupported", **base)

    # --- 4.3 (1) exactly one DPoP header
    if not dpops:
        return _deny("dpop_missing", **base)
    if len(dpops) > 1 or "," in dpops[0]:
        return _deny("dpop_multiple", **base)
    proof = dpops[0].strip()

    # --- 4.3 (2) well-formed JWT
    try:
        hdr, claims, signing_input, sig = parse_compact(proof)
    except JoseError:
        return _deny("dpop_malformed", **base)

    # --- 4.3 (3) required header members and claims present
    for h in ("typ", "alg", "jwk"):
        if h not in hdr:
            return _deny(f"missing_{h}", **base)
    # --- 4.3 (4) typ
    if not isinstance(hdr["typ"], str) or hdr["typ"].lower() != "dpop+jwt":
        return _deny("wrong_typ", **base)
    # --- 4.3 (5) alg: asymmetric, not none, supported
    alg = hdr["alg"]
    if not isinstance(alg, str) or alg.lower() == "none":
        return _deny("alg_none", **base)
    if alg.upper().startswith("HS"):
        return _deny("alg_symmetric", **base)
    if alg not in ASYM_ALGS or alg not in config.allowed_algs:
        return _deny("alg_unsupported", **base)
    # --- 4.3 (7) jwk: public key, no private material
    jwk = hdr["jwk"]
    if not isinstance(jwk, dict):
        return _deny("jwk_invalid", **base)
    if any(k in jwk for k in PRIVATE_MEMBERS):
        return _deny("jwk_private", **base)
    try:
        key = public_key(jwk, alg)
        proof_jkt = thumbprint(jwk)
    except (JoseError, KeyError, TypeError):
        return _deny("jwk_invalid", **base)
    # --- 4.3 (6) signature verifies with jwk
    if not verify_signature(key, alg, signing_input, sig):
        return _deny("bad_signature", **base)

    B = config.bind_claims
    need = ["jti", "iat"] + (["htm"] if "no-htm" not in B else []) + (["htu"] if "no-htu" not in B else [])
    for c in ("jti", "htm", "htu", "iat"):
        if c in need and c not in claims:
            return _deny(f"missing_{c}", **base)
    jti, htm, htu, iat = claims.get("jti"), claims.get("htm"), claims.get("htu"), claims.get("iat")
    if not isinstance(jti, str) or not jti:
        return _deny("missing_jti", **base)
    base["jti"] = jti
    if "no-htm" not in B and not isinstance(htm, str):
        return _deny("missing_htm", **base)
    if "no-htu" not in B and not isinstance(htu, str):
        return _deny("missing_htu", **base)
    base.update(htm=htm if isinstance(htm, str) else None, htu=htu if isinstance(htu, str) else None)
    if isinstance(iat, bool) or not isinstance(iat, (int, float)):
        return _deny("missing_iat", **base)

    # --- 4.3 (8) htm matches the view method (case-sensitive, RFC 9110 section 9.1)
    if "no-htm" not in B and htm != view.method:
        return _deny("htm_mismatch", **base)
    # --- 4.3 (9) htu matches the view URI, ignoring query and fragment
    if "no-htu" not in B:
        ok, why, ch, cv = canon.compare(htu, vurl, config.canon)
        base.update(canon_htu=ch, canon_view=cv)
        if not ok:
            reason = why if why in CHECKS else ("view_invalid" if why.startswith("strict_") else "htu_invalid")
            d = _deny(reason, **base)
            d.reason = why  # keep the precise strict_* code for logs
            return d
        # --- W18 +query: the htu claim's query must equal the view's query
        if "+query" in B:
            qok, qh, qv = bind.compare_query(htu, vurl, config.query_canon)
            if not qok:
                d = _deny("htu_mismatch", **base)
                d.reason = "query_mismatch"
                return d
    # --- W18 +digest: the Content-Digest header must equal the proof's cdig claim
    if "+digest" in B:
        cd = claims.get(bind.DIGEST_CLAIM)
        hv = header_values(headers, "content-digest")
        if not isinstance(cd, str):
            return _reason(_deny("missing_htu", **base), "missing_cdig")
        if len(hv) != 1:
            return _reason(_deny("htu_mismatch", **base), "digest_header_missing" if not hv else "digest_header_multiple")
        if hv[0].strip() != cd.strip():
            return _reason(_deny("htu_mismatch", **base), "digest_mismatch")
    # --- 4.3 (11) iat within the acceptable window
    if abs(now - iat) > config.iat_window:
        return _deny("iat_skew", **base)

    # --- section 7 / RFC 9068: access token
    try:
        th, tc, tsi, tsig = parse_compact(at)
    except JoseError:
        return _deny("token_malformed", **base)
    if str(th.get("typ", "")).lower() not in ("at+jwt", "application/at+jwt"):
        return _deny("token_typ", **base)
    as_alg = config.as_pub_jwk.get("alg", "ES256")
    if th.get("alg") != as_alg:
        return _deny("token_alg", **base)
    try:
        as_key = public_key(config.as_pub_jwk, as_alg)
    except JoseError:
        return _deny("token_signature", **base)
    if not verify_signature(as_key, as_alg, tsi, tsig):
        return _deny("token_signature", **base)
    if tc.get("iss") != config.iss:
        return _deny("token_iss", **base)
    aud = tc.get("aud")
    if not ((isinstance(aud, str) and aud == config.aud) or (isinstance(aud, list) and config.aud in aud)):
        return _deny("token_aud", **base)
    exp = tc.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)) or now >= exp + config.token_leeway:
        return _deny("token_expired", **base)
    nbf = tc.get("nbf")
    if isinstance(nbf, (int, float)) and now + config.token_leeway < nbf:
        return _deny("token_nbf", **base)
    base["sub"] = tc.get("sub")

    # --- 4.3 (10) ath present and equal to the hash of the presented token
    if "no-ath" not in B:
        if "ath" not in claims:
            return _deny("missing_ath", **base)
        if not isinstance(claims["ath"], str) or not hmac.compare_digest(claims["ath"], sha256_b64u(at)):
            return _deny("ath_mismatch", **base)
    # --- 4.3 (12) / 6.1: proof key matches the token's cnf.jkt
    cnf = tc.get("cnf")
    if not isinstance(cnf, dict) or not isinstance(cnf.get("jkt"), str):
        return _deny("token_no_cnf", **base)
    if not hmac.compare_digest(cnf["jkt"], proof_jkt):
        return _deny("jkt_mismatch", **base)
    base["jkt"] = proof_jkt

    # --- 11.1: jti replay (recorded only once all other checks passed)
    if config.jti_cache and not config.cache.add(jti, now):
        return _deny("jti_replay", **base)

    d = Decision(True, "ok", None, **base)
    d.response_headers = {"X-Verified-Sub": str(d.sub or ""), "X-Verified-Jkt": proof_jkt}
    if config.view_mac:
        d.response_headers["X-Verified-View"] = view_mac(config.view_mac_key, jti, view.method, view.uri, proof_jkt)
    return d
