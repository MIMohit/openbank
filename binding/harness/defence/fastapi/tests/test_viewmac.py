import json
import os
import pathlib
import random
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import viewmac  # noqa: E402

VEC = json.loads((HERE.parents[1] / "vectors.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("v", VEC["canon_path"], ids=lambda v: repr(v["in"]))
def test_canon_path(v):
    assert viewmac.canon_path(v["in"]) == v["out"]


@pytest.mark.parametrize("v", VEC["thumbprint"], ids=lambda v: v["jwk"]["kty"])
def test_thumbprint(v):
    assert viewmac.thumbprint(v["jwk"]) == v["jkt"]


@pytest.mark.parametrize("v", VEC["mac"], ids=lambda v: v["uri"])
def test_mac(v):
    assert viewmac.mac(v["key"].encode(), v["jti"], v["method"], v["uri"], v["jkt"]) == v["out"]


@pytest.mark.parametrize("v", VEC["substitute"], ids=lambda v: repr(v["params"]))
def test_substitute(v):
    assert viewmac.substitute(v["template"], v["params"]) == v["out"]


@pytest.mark.parametrize("v", VEC["check"], ids=lambda v: v["name"])
def test_check(v):
    r = viewmac.check(v["key"].encode(), v["headers"]["x-verified-view"], v["headers"]["dpop"],
                      v["method"], v["template"], v["params"])
    assert (r.ok, r.reason) == (v["expect"]["ok"], v["expect"]["reason"])
    if v["expect"]["path"] is not None:
        assert r.path == v["expect"]["path"]


def test_empty_key_refused():
    with pytest.raises(ValueError):
        viewmac.check(b"", [], [], "GET", "/", {})
    with pytest.raises(ValueError):
        viewmac.fastapi_dependency(b"")


def test_differential_canon_against_verifier():
    """Random differential test against verifier.canon.canon_path (skipped if not importable)."""
    sys.path.insert(0, str(HERE.parents[2]))
    try:
        from verifier import canon as vcanon
    except Exception as e:  # pragma: no cover
        pytest.skip(f"verifier not importable: {e}")
    rnd = random.Random(1123)
    alphabet = ["/", ".", "..", "%2e", "%2E", "%2F", "%2f", "%41", "%7e", "a", "B", ";", "%", "%c3", "?", "#", "//", "~", "%25"]
    for _ in range(20000):
        u = "/" + "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 10)))
        assert viewmac.canon_path(u) == vcanon.canon_path(u), u


# ----------------------------------------------------------------------------- FastAPI adapter
fastapi = pytest.importorskip("fastapi")
from fastapi import Depends, FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

KEY = b"adapter-key"
CHK = next(c for c in VEC["check"] if c["name"] == "benign_get")
DPOP = CHK["headers"]["dpop"][0]
JTI, JKT = viewmac.dpop_binding(DPOP)


class Override:  # same shape as the executor's HTTPMethodOverrideASGI (mutates scope["method"])
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            for k, v in scope["headers"]:
                if k == b"x-http-method-override":
                    scope["method"] = v.decode().upper()
        await self.app(scope, receive, send)


def build():
    dep = Depends(viewmac.fastapi_dependency(KEY))
    app = FastAPI(dependencies=[dep])

    def h(request: Request):
        return {"m": request.scope["method"], "path": request.scope["state"]["viewmac"].path}

    app.add_api_route("/api/v1/accounts/{id}", h, methods=["GET", "DELETE", "POST"])
    app.add_api_route("/api/v1/public/{file}", h, methods=["GET"])
    v2 = FastAPI(dependencies=[dep])
    v2.add_api_route("/accounts/{id}", h, methods=["GET"])
    app.mount("/api/v2", v2)
    return TestClient(Override(app))


def hdrs(method, uri, **extra):
    return {"x-verified-view": viewmac.mac(KEY, JTI, method, uri, JKT), "dpop": DPOP, **extra}


def test_adapter_allow_and_template():
    c = build()
    r = c.get("/api/v1/accounts/acc-alice-1", headers=hdrs("GET", "/api/v1/accounts/acc-alice-1"))
    assert r.status_code == 200 and r.json()["path"] == "/api/v1/accounts/acc-alice-1"


def test_adapter_prefix_mount():
    c = build()
    r = c.get("/api/v2/accounts/acc-alice-1", headers=hdrs("GET", "/api/v2/accounts/acc-alice-1"))
    assert r.status_code == 200, r.text
    r = c.get("/api/v2/accounts/acc-alice-1", headers=hdrs("GET", "/api/v1/accounts/acc-alice-1"))
    assert r.status_code == 401


def test_adapter_decoded_param_reencoded():
    c = build()
    r = c.get("/api/v1/public/a%20b%7E", headers=hdrs("GET", "/api/v1/public/a%20b%7e"))
    assert r.status_code == 200, r.text
    assert r.json()["path"] == "/api/v1/public/a%20b~"
    # Starlette routes on the DECODED path, so %2F never reaches {file} (404 before the check)
    assert c.get("/api/v1/public/a%2Fb", headers=hdrs("GET", "/api/v1/public/a%2Fb")).status_code == 404


def test_adapter_method_override_rejected():
    c = build()
    # verifier saw POST; the override makes the executor dispatch DELETE
    r = c.post("/api/v1/accounts/acc-alice-1", headers=hdrs("POST", "/api/v1/accounts/acc-alice-1",
                                                            **{"X-HTTP-Method-Override": "DELETE"}))
    assert r.status_code == 401
    assert r.json()["detail"]["reason"] == "view_mac_mismatch"
    assert r.headers["www-authenticate"].startswith("DPoP")
    # a MAC over the effective method passes
    r = c.post("/api/v1/accounts/acc-alice-1", headers=hdrs("DELETE", "/api/v1/accounts/acc-alice-1",
                                                            **{"X-HTTP-Method-Override": "DELETE"}))
    assert r.status_code == 200 and r.json()["m"] == "DELETE"


def test_adapter_missing_and_duplicate():
    c = build()
    r = c.get("/api/v1/accounts/acc-alice-1", headers={"dpop": DPOP})
    assert r.status_code == 401 and r.json()["detail"]["reason"] == "view_mac_missing"
    good = viewmac.mac(KEY, JTI, "GET", "/api/v1/accounts/acc-alice-1", JKT)
    r = c.get("/api/v1/accounts/acc-alice-1", headers=[("x-verified-view", good), ("x-verified-view", good), ("dpop", DPOP)])
    assert r.status_code == 401 and r.json()["detail"]["reason"] == "view_mac_multiple"
