"""One positive case and one negative test per RFC 9449 section 4.3 / section 7 check.

Mirrors the OIDF FAPI2 DPoP negative-test list (FAPI2SPFinalDpopNegativeTests): expected
outcomes as listed in research/lit/cluster3_testing_measurement.md section 0.
"""
import time

import pytest

from minter import keys as K
from minter.dpop import headers_for, mint_proof
from minter.jose import ath_for
from minter.tokens import mint_access_token
from verifier.core import View, verify

URL = "http://api.bench.test/api/v1/accounts/acc-alice-1"
PATH = "/api/v1/accounts/acc-alice-1"
VIEW = View("GET", PATH, "api.bench.test")


def run(cfg, variant="valid", view=VIEW, htm="GET", htu=URL, **kw):
    return verify(view, headers_for("alice", htm, htu, variant=variant, **kw), cfg)


def test_positive(cfg):
    d = run(cfg)
    assert d.allow and d.reason == "ok" and d.status == 200
    assert d.sub == "alice"
    from minter.jose import thumbprint
    assert d.jkt == thumbprint(K.client_key("alice"))
    assert set(d.response_headers) == {"X-Verified-Sub", "X-Verified-Jkt"}


# OIDF list: expected reject, with the reason code our verifier must give
NEGATIVE = [
    ("multiple_dpop", "dpop_multiple"),
    ("missing_typ", "missing_typ"),
    ("missing_alg", "missing_alg"),
    ("missing_jwk", "missing_jwk"),
    ("missing_jti", "missing_jti"),
    ("missing_htm", "missing_htm"),
    ("missing_htu", "missing_htu"),
    ("missing_iat", "missing_iat"),
    ("missing_ath", "missing_ath"),
    ("wrong_typ", "wrong_typ"),
    ("alg_none", "alg_none"),
    ("alg_hs256", "alg_symmetric"),
    ("bad_signature", "bad_signature"),
    ("private_key_in_jwk", "jwk_private"),
    ("wrong_htm", "htm_mismatch"),      # htm PUT on a GET
    ("lowercase_htm", "htm_mismatch"),
    ("wrong_htu", "htu_mismatch"),      # + "ohnonotagain"
    ("iat_future_1h", "iat_skew"),
    ("iat_past_1h", "iat_skew"),
    ("wrong_ath", "ath_mismatch"),
    ("different_key", "jkt_mismatch"),
    ("jwk_signature_mismatch", "bad_signature"),
    ("no_dpop", "dpop_missing"),
    ("bearer_downgrade", "bearer_downgrade"),
]


@pytest.mark.parametrize("variant,reason", NEGATIVE)
def test_negative(cfg, variant, reason):
    d = run(cfg, variant)
    assert not d.allow and d.status == 401
    assert d.reason == reason
    assert d.www_authenticate().startswith('DPoP error="')


@pytest.mark.parametrize("variant", ["extra_claims", "htu_with_query", "htu_with_fragment"])
def test_accepted_variants(cfg, variant):
    assert run(cfg, variant).allow


def test_malformed_jwt(cfg):
    at = mint_access_token("alice")
    for bad in ["notajwt", "a.b", "a.b.c", "e30.e30", "!!!.e30.", "e30.e30.e30.e30"]:
        d = verify(VIEW, {"Authorization": f"DPoP {at}", "DPoP": bad}, cfg)
        assert not d.allow and d.reason == "dpop_malformed", bad


def test_comma_joined_dpop_is_multiple(cfg):
    h = headers_for("alice", "GET", URL, variant="multiple_dpop")
    h["DPoP"] = ", ".join(h["DPoP"])
    assert verify(VIEW, h, cfg).reason == "dpop_multiple"


def test_reused_jti(cfg):
    at = mint_access_token("alice")
    p = mint_proof(K.client_key("alice"), "GET", URL, at)
    h = {"Authorization": f"DPoP {at}", "DPoP": p}
    assert verify(VIEW, h, cfg).allow
    d = verify(VIEW, h, cfg)
    assert not d.allow and d.reason == "jti_replay"


def test_reused_jti_allowed_when_cache_off(cfg_factory):
    cfg = cfg_factory(jti_cache=False)
    at = mint_access_token("alice")
    h = {"Authorization": f"DPoP {at}", "DPoP": mint_proof(K.client_key("alice"), "GET", URL, at)}
    assert verify(VIEW, h, cfg).allow and verify(VIEW, h, cfg).allow


def test_failed_request_does_not_burn_jti(cfg):
    at = mint_access_token("alice")
    p = mint_proof(K.client_key("alice"), "GET", URL, at)
    other_view = View("GET", "/api/v1/me", "api.bench.test")
    assert verify(other_view, {"Authorization": f"DPoP {at}", "DPoP": p}, cfg).reason == "htu_mismatch"
    assert verify(VIEW, {"Authorization": f"DPoP {at}", "DPoP": p}, cfg).allow


def test_iat_within_window(cfg):
    assert run(cfg, iat_offset=-50).allow and run(cfg, iat_offset=50).allow
    assert run(cfg, iat_offset=-61).reason == "iat_skew"


def test_dpop_scheme_case_insensitive(cfg):
    h = headers_for("alice", "GET", URL)
    h["Authorization"] = "DPOP " + h["Authorization"].split(" ", 1)[1]
    assert verify(VIEW, h, cfg).allow


def test_bearer_with_proof_still_rejected(cfg):
    h = headers_for("alice", "GET", URL)
    h["Authorization"] = "Bearer " + h["Authorization"].split(" ", 1)[1]
    assert verify(VIEW, h, cfg).reason == "bearer_downgrade"


def test_missing_authorization(cfg):
    h = headers_for("alice", "GET", URL)
    del h["Authorization"]
    assert verify(VIEW, h, cfg).reason == "auth_missing"


def test_missing_view(cfg):
    d = verify(View(None, None, None), headers_for("alice", "GET", URL), cfg)
    assert d.reason == "view_missing"


# ---- access token checks (section 7 / RFC 9068)
def _with_token(cfg, at, key="alice"):
    p = mint_proof(K.client_key(key), "GET", URL, at)
    return verify(VIEW, {"Authorization": f"DPoP {at}", "DPoP": p}, cfg)


@pytest.mark.parametrize("kw,reason", [
    ({"exp": int(time.time()) - 10}, "token_expired"),
    ({"aud": "https://other.test"}, "token_aud"),
    ({"iss": "https://evil.test"}, "token_iss"),
    ({"typ": "JWT"}, "token_typ"),
    ({"typ": None}, "token_typ"),
    ({"cnf_jkt": ""}, "token_no_cnf"),
    ({"signature": "AAAA"}, "token_signature"),
])
def test_token_negative(cfg, kw, reason):
    assert _with_token(cfg, mint_access_token("alice", **kw)).reason == reason


def test_token_signed_by_other_key(cfg):
    at = mint_access_token("alice", as_key=K.client_key("bob"))
    assert _with_token(cfg, at).reason == "token_signature"


def test_token_aud_list(cfg):
    assert _with_token(cfg, mint_access_token("alice", aud=["x", "https://api.bench.test"])).allow


def test_bob_token_alice_proof(cfg):
    assert _with_token(cfg, mint_access_token("bob"), key="alice").reason == "jkt_mismatch"


def test_ath_bound_to_presented_token(cfg):
    at1, at2 = mint_access_token("alice"), mint_access_token("alice")
    p = mint_proof(K.client_key("alice"), "GET", URL, at1)
    assert verify(VIEW, {"Authorization": f"DPoP {at2}", "DPoP": p}, cfg).reason == "ath_mismatch"


# ---- VIEW_MAC (CONTRACT section 8)
def test_view_mac(cfg_factory):
    import base64, hashlib, hmac
    cfg = cfg_factory(view_mac=True, view_mac_key=b"k3y")
    v = View("GET", "/api/v1/accounts/./acc-alice-1?x=1", "api.bench.test")
    d = verify(v, headers_for("alice", "GET", URL), cfg)
    assert d.allow
    msg = f"{d.jti}\nGET\n/api/v1/accounts/acc-alice-1\n{d.jkt}".encode()
    exp = "v1;" + base64.urlsafe_b64encode(hmac.new(b"k3y", msg, hashlib.sha256).digest()).rstrip(b"=").decode()
    assert d.response_headers["X-Verified-View"] == exp


def test_view_mac_requires_key(cfg_factory):
    with pytest.raises(ValueError):
        cfg_factory(view_mac=True)
