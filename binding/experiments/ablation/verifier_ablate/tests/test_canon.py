"""HTU_CANON modes: case / default-port variants and non-canonical inputs per mode."""
import pytest

from minter.dpop import headers_for
from verifier import canon
from verifier.core import View, verify

URL = "http://api.bench.test/api/v1/accounts/acc-alice-1"


def dec(cfg, view_uri, htu=URL, host="api.bench.test", proto="http", method="GET"):
    return verify(View(method, view_uri, host, proto), headers_for("alice", "GET", htu), cfg)


# (htu variant, view uri, expected allow per mode)
CASES = [
    ("canonical", URL, "/api/v1/accounts/acc-alice-1", {"rfc3986": True, "none": True, "strict": True}),
    ("htu upper scheme/host", "HTTP://API.BENCH.TEST/api/v1/accounts/acc-alice-1", "/api/v1/accounts/acc-alice-1",
     {"rfc3986": True, "none": False, "strict": True}),
    ("htu default port", "http://api.bench.test:80/api/v1/accounts/acc-alice-1", "/api/v1/accounts/acc-alice-1",
     {"rfc3986": True, "none": False, "strict": True}),
    ("view default port host", URL, "http://api.bench.test:80/api/v1/accounts/acc-alice-1",
     {"rfc3986": True, "none": False, "strict": True}),
    ("view dot segment", URL, "/api/v1/accounts/x/../acc-alice-1", {"rfc3986": True, "none": False, "strict": False}),
    ("view encoded dot segment", URL, "/api/v1/accounts/x/%2e%2e/acc-alice-1",
     {"rfc3986": True, "none": False, "strict": False}),
    ("view encoded unreserved", URL, "/api/v1/accounts/acc-%61lice-1", {"rfc3986": True, "none": False, "strict": False}),
    ("view encoded slash", URL, "/api/v1/accounts%2Facc-alice-1", {"rfc3986": False, "none": False, "strict": False}),
    ("view duplicate slash", URL, "/api/v1//accounts/acc-alice-1", {"rfc3986": False, "none": False, "strict": False}),
    ("view path parameter", URL, "/api/v1/accounts/acc-alice-1;x=1", {"rfc3986": False, "none": False, "strict": False}),
    ("view query ignored", URL, "/api/v1/accounts/acc-alice-1?op=close", {"rfc3986": True, "none": True, "strict": True}),
    ("view path case differs", URL, "/API/v1/accounts/acc-alice-1", {"rfc3986": False, "none": False, "strict": False}),
    ("view trailing slash", URL, "/api/v1/accounts/acc-alice-1/", {"rfc3986": False, "none": False, "strict": False}),
]


@pytest.mark.parametrize("mode", canon.MODES)
@pytest.mark.parametrize("name,htu,view_uri,expect", CASES, ids=[c[0] for c in CASES])
def test_mode_matrix(cfg_factory, mode, name, htu, view_uri, expect):
    d = dec(cfg_factory(canon=mode), view_uri, htu)
    assert d.allow is expect[mode], (mode, name, d.reason)


def test_view_host_case(cfg_factory):
    for mode, ok in (("rfc3986", True), ("none", False), ("strict", True)):
        assert dec(cfg_factory(canon=mode), "/api/v1/accounts/acc-alice-1", host="API.Bench.Test").allow is ok


def test_strict_reasons():
    for u, r in [("http://h/a/../b", "strict_dot_segment"), ("http://h/a%2fb", "strict_encoded_slash"),
                 ("http://h//a", "strict_duplicate_slash"), ("http://h/a;b", "strict_path_parameter"),
                 ("http://h/a%2541", "strict_double_encoding"), ("http://h/a%7e", "strict_encoded_unreserved"),
                 ("http://h/a%c3%a9", "strict_lowercase_hex"), ("http://h/a\\b", "strict_illegal_char"),
                 ("http://u@h/a", "strict_userinfo"), ("http://h/a%zz", "strict_bad_percent"),
                 ("http://h/a%00", "strict_encoded_nul")]:
        with pytest.raises(canon.NonCanonical) as e:
            canon.strict_check(u)
        assert str(e.value) == r, u
    canon.strict_check("http://h/api/v1/accounts/acc-alice-1")


def test_remove_dot_segments_rfc_examples():
    # RFC 3986 section 5.2.4 examples
    assert canon.remove_dot_segments("/a/b/c/./../../g") == "/a/g"
    assert canon.remove_dot_segments("mid/content=5/../6") == "mid/6"


def test_normalise_rfc3986():
    assert canon.normalise_rfc3986("HTTP://Ex.COM:80/%7Ea/./b/../c%2f?q#f") == "http://ex.com/~a/c%2F"
    assert canon.normalise_rfc3986("https://ex.com:443") == "https://ex.com/"
    assert canon.normalise_rfc3986("http://ex.com:8080/x") == "http://ex.com:8080/x"


def test_unknown_mode(cfg_factory):
    with pytest.raises(ValueError):
        cfg_factory(canon="bogus")
