"""Path-based authorization policy engine for the bench PDP (W12, E4).

A policy decision point (PDP) applies an *ownership/role* policy to the view v(r) that the
verifier already saw (method, URI, host). It answers one question: may this subject perform
the operation that this path denotes? Like a real API gateway, it matches the **path** of the
request against a rule list; it does NOT re-route or parse the request the way the backend
framework will. That gap is the object of study.

Two realistic policy *styles* are shipped (CONTRACT §12 / task E4 item 1). Both are written
the way a gateway operator writes them in practice:

  * ``allowlist`` — default-DENY whitelist of the subject's own resources, by prefix and
    exact match. This is how a per-tenant edge policy or an OPA "allow if path startswith"
    rule reads. (styles used: prefix, exact)
  * ``blocklist`` — default-ALLOW for an authenticated principal, with explicit DENY rules
    for admin routes and an ownership regex on the account id. This is how an RBAC filter or
    a Spring-Security ``authorizeHttpRequests().requestMatchers("/api/*/admin/**").denyAll()``
    rule reads. (styles used: regex, segment-boundaried regex)

Each rule records how it was written so the report can attribute a bypass to a rule style.

Normalisation: by default the policy matches the **raw** view path (``POLICY_NORMALIZE=off``),
exactly as a gateway that keys on ``$request_uri`` / ``X-Original-URI`` does. ``rfc3986`` runs
the verifier's own canonicalisation (remove_dot_segments, %-decoding of unreserved, no
slash-collapse, no ``.json``/``;`` stripping, no case-folding) before matching, to measure
which differential classes survive a normalising PDP.

The subject is fixed to ``alice`` for E4 (the malicious-but-legitimate client). The permitted
set mirrors the task statement:
  /api/v1/accounts/acc-alice-1 (+subpaths), /api/v2/accounts/acc-alice-1, /api/v1/me,
  /api/v1/public/*, /api/v1/health, /api/v1/transfers, /api/v1/graphql (getProfile).
Not permitted: admin routes, any account id != acc-alice-1 (e.g. acc-bob-1).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

# The verifier's canonicaliser (same package is copied into the image).
from verifier import canon

ALICE_ACCT = "acc-alice-1"


@dataclass
class Rule:
    id: str
    style: str          # "prefix" | "exact" | "regex" | "suffix"
    pattern: str
    effect: str         # "allow" | "deny"
    note: str = ""

    def matches(self, path: str) -> bool:
        if self.style == "prefix":
            # segment-aware prefix: pattern, or pattern followed by a sub-path / end.
            return path == self.pattern or path.startswith(self.pattern.rstrip("/") + "/") \
                or path.startswith(self.pattern)
        if self.style == "exact":
            return path == self.pattern
        if self.style == "suffix":
            return path.endswith(self.pattern)
        if self.style == "regex":
            return re.search(self.pattern, path) is not None
        raise ValueError(f"unknown rule style {self.style!r}")


@dataclass
class PolicyDecision:
    effect: str             # "allow" | "deny"
    rule_id: str            # matched rule id, or "<default>"
    matched_path: str       # the path the policy actually matched on (post-normalisation)
    policy: str
    normalize: str


# ──────────────────────────── policy A: ownership allow-list ────────────────────────
# Default DENY. Enumerate alice's own resources by prefix/exact. This is the common
# "whitelist the tenant's paths" edge rule. It is bypassed whenever a crafted path keeps
# one of these prefixes at its START but the backend routes it elsewhere (e.g. a
# dot-segment traversal `/api/v1/accounts/acc-alice-1/../acc-bob-1` that Kestrel resolves).
ALLOWLIST: List[Rule] = [
    Rule("allow-v1-own", "prefix", f"/api/v1/accounts/{ALICE_ACCT}", "allow",
         "alice's v1 account and subpaths (actions, etc.)"),
    Rule("allow-v2-own", "prefix", f"/api/v2/accounts/{ALICE_ACCT}", "allow",
         "alice's v2 account"),
    Rule("allow-me", "exact", "/api/v1/me", "allow", "self profile"),
    Rule("allow-public", "prefix", "/api/v1/public/", "allow", "public files"),
    Rule("allow-health", "exact", "/api/v1/health", "allow", "health"),
    Rule("allow-transfers", "exact", "/api/v1/transfers", "allow", "create transfer"),
    Rule("allow-graphql", "exact", "/api/v1/graphql", "allow", "graphql getProfile"),
]
ALLOWLIST_DEFAULT = "deny"

# ──────────────────────────── policy B: role deny-list ──────────────────────────────
# Default ALLOW for the authenticated principal, with explicit DENY rules. Admin is blocked
# by a segment-boundaried regex (so it will not also block a hypothetical
# `/api/v1/administrators-public`), and ownership is enforced by an id-capturing regex that
# must equal alice's account. This is how an RBAC request-matcher reads. It is bypassed by
# anything that stops the DENY regex from firing while the backend still routes to admin /
# another id (case folding, matrix params, `//`, `.json` as `:format`, encoded slash).
BLOCKLIST: List[Rule] = [
    Rule("deny-admin", "regex", r"^/api/v[12]/admin(?:/|$)", "deny",
         "admin segment, boundaried so it does not over-match"),
    Rule("deny-foreign-account", "regex",
         rf"^/api/v[12]/accounts/(?!{re.escape(ALICE_ACCT)}(?:/|$))[^/]+", "deny",
         "account id segment that is not alice's"),
]
BLOCKLIST_DEFAULT = "allow"

POLICIES = {
    "allowlist": (ALLOWLIST, ALLOWLIST_DEFAULT),
    "blocklist": (BLOCKLIST, BLOCKLIST_DEFAULT),
}


def _path_of(view_uri: str) -> str:
    """Extract the path from an origin-form or absolute-form view URI, dropping query/frag."""
    u = view_uri or ""
    m = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/]*(/[^?#]*|)", u)
    if m:
        return m.group(1) or "/"
    return canon.strip_query_fragment(u)


def normalise(path: str, mode: str) -> str:
    if mode == "off" or not path:
        return path
    if mode == "rfc3986":
        # Same syntax-based normalisation the verifier applies to compare htu (canon.py):
        # remove_dot_segments + %-decode unreserved + upper-case hex. No slash collapse,
        # no ';'/'.json' stripping, no case folding of the path.
        try:
            return canon.normalise_path(path)
        except Exception:
            return path
    raise ValueError(f"unknown POLICY_NORMALIZE {mode!r}")


def decide(view_uri: str, policy: str = "allowlist", normalize: str = "off") -> PolicyDecision:
    """Apply the named policy to the view path. First matching rule wins."""
    rules, default = POLICIES[policy]
    raw_path = _path_of(view_uri)
    path = normalise(raw_path, normalize)
    for r in rules:
        if r.matches(path):
            return PolicyDecision(r.effect, r.id, path, policy, normalize)
    return PolicyDecision(default, "<default>", path, policy, normalize)
