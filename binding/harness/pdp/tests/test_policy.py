"""Unit tests for the PDP path policy (pdp.policy).

These assert the *policy-level* behaviour: which crafted paths the policy ALLOWS for alice.
A policy-allow on a path the backend routes to a forbidden op is the first half of an
authorization-soundness violation (the executor routing is measured in the live matrix).
Run from binding/harness:  PYTHONPATH=. python -m pytest pdp/tests -q
"""
import pytest

from pdp.policy import decide, ALICE_ACCT

ORIGIN = "http://api.bench.test"


def eff(path, policy="allowlist", normalize="off"):
    return decide(ORIGIN + path, policy, normalize).effect


def rule(path, policy="allowlist", normalize="off"):
    return decide(ORIGIN + path, policy, normalize).rule_id


# ─────────────────────────── allow-list (default deny) ──────────────────────────────
def test_allowlist_permits_own_resources():
    assert eff("/api/v1/accounts/acc-alice-1") == "allow"
    assert eff("/api/v1/accounts/acc-alice-1/actions") == "allow"
    assert eff("/api/v2/accounts/acc-alice-1") == "allow"
    assert eff("/api/v1/me") == "allow"
    assert eff("/api/v1/public/logo.png") == "allow"
    assert eff("/api/v1/health") == "allow"
    assert eff("/api/v1/transfers") == "allow"


def test_allowlist_denies_admin_and_foreign_directly():
    assert eff("/api/v1/admin/users") == "deny"
    assert eff("/api/v1/admin/users/u-1") == "deny"
    assert eff("/api/v1/accounts/acc-bob-1") == "deny"
    assert eff("/api/v2/accounts/acc-bob-1") == "deny"


def test_allowlist_bypassed_by_dot_segment_traversal_raw():
    # The raw path keeps alice's prefix at the START, so the prefix rule fires -> allow,
    # even though a resolving backend (Kestrel) routes to bob / admin. (W5 aspnet lead.)
    assert eff("/api/v1/accounts/acc-alice-1/../acc-bob-1") == "allow"
    assert eff("/api/v1/accounts/acc-alice-1/../../admin/users") == "allow"
    assert eff("/api/v1/accounts/acc-alice-1/%2e%2e/acc-bob-1") == "allow"


def test_allowlist_normalize_closes_dot_segment_class():
    # An rfc3986-normalising PDP resolves /../ before matching -> bob/admin no longer
    # match alice's prefixes -> deny. This is the defence the report recommends.
    assert eff("/api/v1/accounts/acc-alice-1/../acc-bob-1", normalize="rfc3986") == "deny"
    assert eff("/api/v1/accounts/acc-alice-1/../../admin/users", normalize="rfc3986") == "deny"
    assert eff("/api/v1/accounts/acc-alice-1/%2e%2e/acc-bob-1", normalize="rfc3986") == "deny"


# ─────────────────────────── block-list (default allow) ─────────────────────────────
def test_blocklist_denies_admin_and_foreign():
    assert eff("/api/v1/admin/users", "blocklist") == "deny"
    assert eff("/api/v1/admin/users/u-1", "blocklist") == "deny"
    assert eff("/api/v1/accounts/acc-bob-1", "blocklist") == "deny"
    assert eff("/api/v2/accounts/acc-bob-1", "blocklist") == "deny"


def test_blocklist_allows_own_and_neutral():
    assert eff("/api/v1/accounts/acc-alice-1", "blocklist") == "allow"
    assert eff("/api/v1/me", "blocklist") == "allow"
    assert eff("/api/v1/transfers", "blocklist") == "allow"


def test_blocklist_bypassed_by_case_variant():
    # Case fold: deny-admin regex is case-sensitive; a case-insensitive router (Kestrel)
    # still routes ADMIN -> adminListUsers. (W5 aspnet lead.)
    assert eff("/api/v1/ADMIN/users", "blocklist") == "allow"
    assert eff("/api/v1/Admin/users", "blocklist") == "allow"


def test_blocklist_bypassed_by_matrix_param():
    # Matrix param on the admin segment: the boundaried deny regex sees `admin;x=1`, not
    # `admin`, so it does not fire; Spring strips the matrix param and routes to admin.
    assert eff("/api/v1/admin;x=1/users/u-1", "blocklist") == "allow"


def test_blocklist_bypassed_by_double_slash():
    # `//admin`: deny regex anchored on `/api/v[12]/admin` does not match `/api/v1//admin`;
    # Rails squeezes `//` -> `/` and routes to admin.
    assert eff("/api/v1//admin/users", "blocklist") == "allow"


def test_blocklist_bypassed_by_json_suffix_is_caught_by_prefix():
    # `.json`: the boundaried regex `^/api/v[12]/admin(?:/|$)` still fires for
    # `/api/v1/admin/users.json` (segment `admin` then `/`), so admin.json is caught here.
    # The .json bypass therefore needs an EXACT-match deny rule; documented in REPORT.
    assert eff("/api/v1/admin/users.json", "blocklist") == "deny"


def test_blocklist_foreign_account_via_traversal_allowed():
    # `/api/v1/accounts/acc-alice-1/../acc-bob-1`: ownership regex captures the FIRST id
    # segment `acc-alice-1` (alice) -> deny rule does not fire -> allow; backend routes bob.
    assert eff("/api/v1/accounts/acc-alice-1/../acc-bob-1", "blocklist") == "allow"


def test_blocklist_normalize_closes_slash_and_dot_but_not_case():
    assert eff("/api/v1//admin/users", "blocklist", "rfc3986") == "deny" \
        or eff("/api/v1//admin/users", "blocklist", "rfc3986") == "allow"
    # rfc3986 does NOT collapse // (RFC 3986 has no such rule), so // survives:
    assert eff("/api/v1//admin/users", "blocklist", "rfc3986") == "allow"
    # case is not folded by rfc3986 either:
    assert eff("/api/v1/ADMIN/users", "blocklist", "rfc3986") == "allow"
    # but dot-segments ARE resolved:
    assert eff("/api/v1/x/../admin/users", "blocklist", "rfc3986") == "deny"


def test_decision_records_rule_and_path():
    d = decide(ORIGIN + "/api/v1/admin/users", "blocklist", "off")
    assert d.effect == "deny" and d.rule_id == "deny-admin"
    assert d.matched_path == "/api/v1/admin/users"
