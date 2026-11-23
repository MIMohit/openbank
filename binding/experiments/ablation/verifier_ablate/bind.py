"""W18 ablation: binding-claim variants for the reference verifier (A1).

BIND_CLAIMS is a comma-separated list. Tokens:
  full      (default) RFC 9449 section 4.3 exactly as the reference verifier: htm + htu (path, query and
            fragment ignored) + ath.
  no-htm    do not require or check the htm claim.
  no-htu    do not require or check the htu claim.
  no-ath    do not require or check the ath claim.
  +query    the htu claim INCLUDES the query string and the verifier compares it with the view's query
            (QUERY_CANON=rfc3986|exact|sorted, default rfc3986). Absence is bound too: an htu without a
            query only matches a view without a query (an empty "?" counts as no query).
  +digest   the proof carries a claim `cdig` whose value is the RFC 9530 Content-Digest field value of
            the request content (sha-256 member). The verifier requires exactly one Content-Digest header
            and requires it to equal the `cdig` claim byte-for-byte (after OWS trim). The verifier does
            NOT see the body behind an auth_request/forward-auth edge (nginx sends the subrequest with
            proxy_pass_request_body off), so body-vs-header integrity is checked by a separate hop that
            does see the body (digest_gate.py, RFC 9530 section 2 recipient check). Both halves are needed
            for soundness; see experiments/ablation/REPORT.md section A1.
Tokens combine, e.g. "+query,+digest". "full" alone is the reference behaviour.
`cdig` is NOT a registered JWT claim: no standard DPoP body-binding claim exists (RFC 9449 section 4.2
lets a proof carry additional claims). It is used here only as an experimental binding.
"""
from __future__ import annotations

import base64
import hashlib
import re

from . import canon

TOKENS = ("full", "no-htm", "no-htu", "no-ath", "+query", "+digest")
QUERY_MODES = ("rfc3986", "exact", "sorted")
DIGEST_CLAIM = "cdig"


def parse(spec: str | None) -> frozenset[str]:
    toks = [t.strip() for t in (spec or "full").split(",") if t.strip()]
    for t in toks:
        if t not in TOKENS:
            raise ValueError(f"BIND_CLAIMS token {t!r} not in {TOKENS}")
    s = frozenset(t for t in toks if t != "full")
    return s


def label(s: frozenset[str]) -> str:
    return ",".join(sorted(s)) if s else "full"


def _query_of(u: str) -> str:
    q = canon.split(u)["query"]
    return q or ""


def canon_query(q: str, mode: str) -> str:
    if mode == "exact":
        return q
    if mode == "rfc3986":
        return canon.normalise_pct(q)
    if mode == "sorted":
        parts = [canon.normalise_pct(p) for p in q.split("&") if p != ""]
        return "&".join(sorted(parts, key=lambda p: p.split("=", 1)[0]))  # stable: keeps dup order
    raise ValueError(f"QUERY_CANON must be one of {QUERY_MODES}")


def compare_query(htu: str, view_url: str, mode: str) -> tuple[bool, str, str]:
    a, b = canon_query(_query_of(htu), mode), canon_query(_query_of(view_url), mode)
    return a == b, a, b


def content_digest(body: bytes) -> str:
    """RFC 9530 Content-Digest field value with a single sha-256 member."""
    return "sha-256=:" + base64.b64encode(hashlib.sha256(body).digest()).decode() + ":"


_MEMBER = re.compile(r"^\s*([a-z0-9_-]+)\s*=\s*:([A-Za-z0-9+/=]*):\s*$")


def parse_digest(value: str) -> dict[str, bytes]:
    """Parse a Content-Digest dictionary (RFC 8941 byte sequences). Raises ValueError."""
    out: dict[str, bytes] = {}
    for member in value.split(","):
        m = _MEMBER.match(member)
        if not m:
            raise ValueError("digest_malformed")
        out[m.group(1)] = base64.b64decode(m.group(2), validate=True)
    return out


def body_matches(value: str, body: bytes) -> bool:
    try:
        d = parse_digest(value)
    except Exception:
        return False
    return "sha-256" in d and d["sha-256"] == hashlib.sha256(body).digest()
