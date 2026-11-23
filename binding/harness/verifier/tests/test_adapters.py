"""Adapter tests: run the real HTTP server in-process and call each adapter."""
import http.client
import json
import threading

import pytest

from minter.dpop import headers_for
from verifier.server import make_server

PATH = "/api/v1/accounts/acc-alice-1"
URL = "http://api.bench.test" + PATH


@pytest.fixture
def server(cfg_factory, tmp_path):
    def start(**cfgkw):
        view_dup = cfgkw.pop("view_dup", "first")
        log = tmp_path / "verifier.jsonl"
        srv = make_server(cfg_factory(**cfgkw), port=0, host="127.0.0.1", log_path=str(log),
                          log_stdout=False, view_dup=view_dup)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        started.append(srv)
        return srv.server_address[1], log
    started = []
    yield start
    for s in started:
        s.shutdown()
        s.server_close()


def call(port, method, target, headers):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
    for k, v in headers:
        c.putheader(k, v)
    c.endheaders()
    r = c.getresponse()
    body = json.loads(r.read() or b"{}")
    return r.status, dict(r.getheaders()), body


def auth(method="GET", htu=URL, variant="valid"):
    h = headers_for("alice", method, htu, variant=variant)
    out = [("Authorization", h["Authorization"])]
    if "DPoP" in h:
        for p in (h["DPoP"] if isinstance(h["DPoP"], list) else [h["DPoP"]]):
            out.append(("DPoP", p))
    return out


def fwd(method="GET", uri=PATH, host="api.bench.test"):
    return [("X-Forwarded-Method", method), ("X-Forwarded-Proto", "http"), ("X-Forwarded-Host", host),
            ("X-Forwarded-Uri", uri), ("Host", "verifier:9100")]


def orig(method="GET", uri=PATH, host="api.bench.test"):
    return [("X-Original-Method", method), ("X-Original-URI", uri), ("X-Original-Host", host),
            ("Host", "verifier:9100")]


def test_health(server):
    port, _ = server()
    s, _, b = call(port, "GET", "/health", [("Host", "x")])
    assert s == 200 and b["status"] == "ok"


def test_unknown_path_404(server):
    port, _ = server()
    assert call(port, "GET", "/authz/other", [("Host", "x")])[0] == 404
    assert call(port, "GET", "/authz/envoyX/api", [("Host", "x")])[0] == 404


@pytest.mark.parametrize("adapter_method", ["GET", "POST", "PUT", "DELETE"])
def test_fwd_allow_any_method(server, adapter_method):
    port, log = server()
    s, h, b = call(port, adapter_method, "/authz/fwd", fwd() + auth())
    assert s == 200 and b["decision"] == "allow"
    assert h["X-Verified-Sub"] == "alice" and h["X-Verified-Jkt"]
    rec = json.loads(log.read_text().splitlines()[-1])
    assert rec["adapter"] == "fwd" and rec["decision"] == "allow" and rec["view_uri"] == PATH
    for k in ("ts", "jti", "view_method", "view_host", "htm", "htu", "canon_mode", "reason", "sub", "jkt"):
        assert k in rec


def test_fwd_deny_wrong_method(server):
    port, log = server()
    s, h, b = call(port, "GET", "/authz/fwd", fwd(method="DELETE") + auth())
    assert s == 401 and b["reason"] == "htm_mismatch"
    assert h["WWW-Authenticate"].startswith('DPoP error="invalid_dpop_proof"')
    rec = json.loads(log.read_text().splitlines()[-1])
    assert rec["decision"] == "deny" and rec["jti"]


def test_fwd_missing_view_headers_fail_closed(server):
    port, _ = server()
    s, _, b = call(port, "GET", "/authz/fwd", [("Host", "verifier")] + auth())
    assert s == 401 and b["reason"] == "view_missing"


def test_orig_allow_and_query_ignored(server):
    port, _ = server()
    s, _, _ = call(port, "GET", "/authz/orig", orig(uri=PATH + "?op=close") + auth())
    assert s == 200


def test_orig_host_fallback(server):
    port, _ = server()
    hdrs = [("X-Original-Method", "GET"), ("X-Original-URI", PATH), ("Host", "api.bench.test")]
    assert call(port, "GET", "/authz/orig", hdrs + auth())[0] == 200


def test_orig_deny_other_account(server):
    port, _ = server()
    s, _, b = call(port, "GET", "/authz/orig", orig(uri="/api/v1/accounts/acc-bob-1") + auth())
    assert s == 401 and b["reason"] == "htu_mismatch"


def test_orig_view_mac(server):
    port, _ = server(view_mac=True, view_mac_key=b"secret")
    s, h, _ = call(port, "GET", "/authz/orig", orig() + auth())
    assert s == 200 and h["X-Verified-View"].startswith("v1;")


def test_envoy_allow(server):
    port, log = server()
    s, h, _ = call(port, "GET", "/authz/envoy" + PATH + "?x=1", [("Host", "api.bench.test")] + auth())
    assert s == 200 and h["X-Verified-Sub"] == "alice"
    rec = json.loads(log.read_text().splitlines()[-1])
    assert rec["adapter"] == "envoy" and rec["view_uri"] == PATH + "?x=1" and rec["view_method"] == "GET"


def test_envoy_method_from_request(server):
    port, _ = server()
    s, _, b = call(port, "DELETE", "/authz/envoy" + PATH, [("Host", "api.bench.test")] + auth())
    assert s == 401 and b["reason"] == "htm_mismatch"


def test_envoy_raw_target_not_decoded(server):
    port, _ = server(canon="strict")
    s, _, b = call(port, "GET", "/authz/envoy/api/v1/accounts%2Facc-alice-1", [("Host", "api.bench.test")] + auth())
    assert s == 401 and b["reason"] == "strict_encoded_slash"


@pytest.mark.parametrize("variant,reason", [("no_dpop", "dpop_missing"), ("multiple_dpop", "dpop_multiple"),
                                            ("bearer_downgrade", "bearer_downgrade")])
def test_request_level_variants_over_http(server, variant, reason):
    port, _ = server()
    s, _, b = call(port, "GET", "/authz/orig", orig() + auth(variant=variant))
    assert s == 401 and b["reason"] == reason


def test_replay_over_http(server):
    port, _ = server()
    a = auth()
    assert call(port, "GET", "/authz/fwd", fwd() + a)[0] == 200
    s, _, b = call(port, "GET", "/authz/fwd", fwd() + a)
    assert s == 401 and b["reason"] == "jti_replay"


@pytest.mark.parametrize("policy,expect", [("first", 200), ("last", 401), ("reject", 401)])
def test_duplicate_view_header_policy(server, policy, expect):
    port, log = server(view_dup=policy)
    hdrs = fwd() + [("X-Forwarded-Uri", "/api/v1/admin/users")] + auth()
    assert call(port, "GET", "/authz/fwd", hdrs)[0] == expect
    assert json.loads(log.read_text().splitlines()[-1])["view_dup"] is True


def test_post_body_is_drained(server):
    port, _ = server()
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    for _ in range(2):  # keep-alive: second request must parse cleanly
        h = dict(orig()); h.update(dict(auth()))
        c.request("POST", "/authz/orig", body=b'{"a":1}', headers=h)
        r = c.getresponse(); r.read()
        assert r.status == 200
