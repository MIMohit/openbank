"""W18: BIND_CLAIMS / QUERY_CANON variants and the digest gate's body check."""
from minter import keys as K
from minter.dpop import content_digest, mint_bound, mint_proof
from minter.tokens import mint_access_token
from verifier import bind
from verifier.core import View, verify

H = "http://api.bench.test"
P = "/api/v1/accounts/acc-alice-1/actions"


def _req(cfg, method, uri, authz, proof, extra=()):
    return verify(View(method, uri, "api.bench.test"), [("Authorization", authz), ("DPoP", proof), *extra], cfg)


def test_full_ignores_query(cfg_factory):
    cfg = cfg_factory()
    a, p, _, _ = mint_bound("alice", "POST", H + P, query="op=freeze")
    assert _req(cfg, "POST", P + "?op=close", a, p).allow


def test_query_binds(cfg_factory):
    cfg = cfg_factory(bind_claims=bind.parse("+query"))
    a, p, _, _ = mint_bound("alice", "POST", H + P, query="op=freeze", bind_query=True)
    assert _req(cfg, "POST", P + "?op=freeze", a, p).allow
    a, p, _, _ = mint_bound("alice", "POST", H + P, query="op=freeze", bind_query=True)
    d = _req(cfg, "POST", P + "?op=close", a, p)
    assert not d.allow and d.reason == "query_mismatch"
    a, p, _, _ = mint_bound("alice", "GET", H + "/api/v1/me", bind_query=True)
    assert not _req(cfg, "GET", "/api/v1/me?x=1", a, p).allow      # absence is bound


def test_query_canon_modes(cfg_factory):
    for mode, ok_reenc, ok_sorted in (("exact", False, False), ("rfc3986", True, False), ("sorted", True, True)):
        cfg = cfg_factory(bind_claims=bind.parse("+query"), query_canon=mode)
        a, p, _, _ = mint_bound("alice", "GET", H + "/api/v1/me", query="b=%7e1&a=2", bind_query=True)
        assert _req(cfg, "GET", "/api/v1/me?b=~1&a=2", a, p).allow is ok_reenc
        a, p, _, _ = mint_bound("alice", "GET", H + "/api/v1/me", query="b=1&a=2", bind_query=True)
        assert _req(cfg, "GET", "/api/v1/me?a=2&b=1", a, p).allow is ok_sorted


def test_digest_header_binding(cfg_factory):
    cfg = cfg_factory(bind_claims=bind.parse("+digest"))
    body = b'{"operationName":"getProfile"}'
    a, p, _, cd = mint_bound("alice", "POST", H + "/api/v1/graphql", body=body, bind_digest=True)
    assert _req(cfg, "POST", "/api/v1/graphql", a, p, [("Content-Digest", cd)]).allow
    a, p, _, cd = mint_bound("alice", "POST", H + "/api/v1/graphql", body=body, bind_digest=True)
    assert _req(cfg, "POST", "/api/v1/graphql", a, p).reason == "digest_header_missing"
    a, p, _, cd = mint_bound("alice", "POST", H + "/api/v1/graphql", body=body, bind_digest=True)
    d = _req(cfg, "POST", "/api/v1/graphql", a, p, [("Content-Digest", content_digest(b"{}"))])
    assert d.reason == "digest_mismatch"
    a, p, _, cd = mint_bound("alice", "POST", H + "/api/v1/graphql", body=body)   # no cdig claim
    assert _req(cfg, "POST", "/api/v1/graphql", a, p, [("Content-Digest", cd or "x")]).reason == "missing_cdig"


def test_body_matches():
    body = b"abc"
    assert bind.body_matches(content_digest(body), body)
    assert not bind.body_matches(content_digest(body), b"abd")
    assert not bind.body_matches("sha-512=:AAAA:", body)
    assert not bind.body_matches("garbage", body)


def test_no_htm_no_htu_no_ath(cfg_factory):
    at = mint_access_token("alice")
    key = K.client_key("alice")
    cfg = cfg_factory(bind_claims=bind.parse("no-htm"))
    assert verify(View("DELETE", "/api/v1/me", "api.bench.test"),
                  [("Authorization", f"DPoP {at}"), ("DPoP", mint_proof(key, "GET", H + "/api/v1/me", at))], cfg).allow
    cfg = cfg_factory(bind_claims=bind.parse("no-htu"))
    assert verify(View("GET", "/api/v1/admin/users", "api.bench.test"),
                  [("Authorization", f"DPoP {at}"), ("DPoP", mint_proof(key, "GET", H + "/api/v1/me", at))], cfg).allow
    cfg = cfg_factory(bind_claims=bind.parse("no-ath"))
    assert verify(View("GET", "/api/v1/me", "api.bench.test"),
                  [("Authorization", f"DPoP {at}"),
                   ("DPoP", mint_proof(key, "GET", H + "/api/v1/me", at, include_ath=False))], cfg).allow
    cfg = cfg_factory()   # full still rejects all three
    assert not verify(View("DELETE", "/api/v1/me", "api.bench.test"),
                      [("Authorization", f"DPoP {at}"), ("DPoP", mint_proof(key, "GET", H + "/api/v1/me", at))], cfg).allow
