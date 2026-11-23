"""Minter: keys, thumbprints, token shape, CLI, and the E6 signers (round trips)."""
import json
import subprocess
import sys
from pathlib import Path

from minter import cavage, rfc9421
from minter import keys as K
from minter.dpop import decode_unverified, headers_for
from minter.jose import public_jwk, thumbprint

HARNESS = Path(__file__).resolve().parents[2]


def test_rfc7638_thumbprint_vector():
    # RFC 7638 section 3.1 is RSA; use the RFC 7517 A.1 EC key and cross-check with the verifier impl.
    from verifier.jose import thumbprint as vt
    k = {"kty": "EC", "crv": "P-256", "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
         "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}
    assert thumbprint(k) == vt(k)
    rsa = {"kty": "RSA", "e": "AQAB", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"}
    assert vt(rsa) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


def test_keys_files(keys_dir):
    for f in ("as_priv", "as_pub", "client_alice", "client_bob"):
        assert (keys_dir / f"{f}.jwk").exists()
    assert "d" not in K.load("as_pub")
    assert K.load("client_alice")["kid"] == thumbprint(K.client_key("alice"))
    assert thumbprint(K.client_key("alice")) != thumbprint(K.client_key("bob"))


def test_token_and_proof_shape():
    h = headers_for("alice", "GET", "http://api.bench.test/api/v1/me")
    at = h["Authorization"].split(" ", 1)[1]
    th, tc = decode_unverified(at)
    assert th["typ"] == "at+jwt" and th["alg"] == "ES256"
    assert tc["iss"] == "https://as.bench.test" and tc["aud"] == "https://api.bench.test"
    assert tc["exp"] - tc["iat"] == 3600 and tc["cnf"]["jkt"] == thumbprint(K.client_key("alice"))
    ph, pc = decode_unverified(h["DPoP"])
    assert ph["typ"] == "dpop+jwt" and ph["alg"] == "ES256" and "d" not in ph["jwk"]
    assert set(pc) == {"jti", "htm", "htu", "iat", "ath"}


def test_cli(keys_dir):
    out = subprocess.run([sys.executable, "-m", "minter.cli", "mint", "--client", "alice", "--htm", "GET",
                          "--htu", "http://api.bench.test/api/v1/accounts/acc-alice-1"],
                         cwd=HARNESS, capture_output=True, text=True, check=True,
                         env={"BH_KEYS_DIR": str(keys_dir), "PATH": "/usr/bin:/bin"})
    j = json.loads(out.stdout)
    assert j["Authorization"].startswith("DPoP ") and j["DPoP"].count(".") == 2 and j["jti"]


def test_rfc9421_roundtrip_and_coverage():
    key = K.client_key("alice"); pub = public_jwk(key)
    url = "http://api.bench.test/api/v1/accounts/acc-alice-1/actions?op=freeze"
    hdrs = [("Host", "api.bench.test"), ("Content-Type", "application/json")]
    add = rfc9421.sign_request("POST", url, hdrs, b"{}", key, components="full")
    allh = hdrs + add
    assert rfc9421.verify_request("POST", url, allh, b"{}", pub) == (True, "ok")
    # query dispatch change breaks @target-uri coverage
    assert not rfc9421.verify_request("POST", url.replace("freeze", "close"), allh, b"{}", pub)[0]
    # path-only coverage: same signature verifies for a different method and query (under-binding)
    add2 = rfc9421.sign_request("POST", url, hdrs, b"{}", key, components="path-only")
    assert rfc9421.verify_request("DELETE", url.replace("freeze", "close"), hdrs + add2, b"", pub) == (True, "ok")
    assert rfc9421.verify_request("POST", url, hdrs + add2, b"", pub, required=["@method"])[1] == \
        "component_not_covered:@method"


def test_rfc9421_spec_base_format():
    params = rfc9421.signature_params(("@method", "@authority", "@path"), 1618884473, "test-key-ecc-p256")
    base = rfc9421.signature_base("POST", "https://example.com/foo?param=Value&Pet=dog", [], ("@method", "@authority", "@path"), params)
    assert base.decode() == ('"@method": POST\n"@authority": example.com\n"@path": /foo\n'
                             '"@signature-params": ("@method" "@authority" "@path");created=1618884473;'
                             'keyid="test-key-ecc-p256";alg="ecdsa-p256-sha256"')


def test_cavage_roundtrip_and_berlin_group_underbinding():
    key = K.client_key("alice"); pub = public_jwk(key)
    hdrs = [("Host", "api.bench.test")]
    add = cavage.sign_request("POST", "/api/v1/transfers", hdrs, b"{}", key, covered="berlin-group")
    allh = hdrs + add
    assert cavage.verify_request("POST", "/api/v1/transfers", allh, b"{}", pub) == (True, "ok")
    # no (request-target): replays to another endpoint/method verify
    assert cavage.verify_request("DELETE", "/api/v1/accounts/acc-bob-1", allh, b"{}", pub) == (True, "ok")
    add2 = cavage.sign_request("POST", "/api/v1/transfers", hdrs, b"{}", key, covered="with-target")
    assert not cavage.verify_request("DELETE", "/api/v1/transfers", hdrs + add2, b"{}", pub)[0]
    assert cavage.verify_request("POST", "/api/v1/transfers", hdrs + add2, b"{}", pub)[0]
