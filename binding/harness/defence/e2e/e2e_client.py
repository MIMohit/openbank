"""End-to-end check of a PATCHED executor (DEFENCE=db) against the real verifier (VIEW_MAC=on).

The gateway is emulated: for each case the client mints a token + proof (minter), asks the
verifier's /authz/orig adapter to authorise the GATEWAY's view, takes X-Verified-View from the
allow response, and sends the raw request bytes to the executor with that header. A control
executor with DEFENCE=off receives the same request (a fresh proof and verifier call).

Usage (from binding/harness): PYTHONPATH=. verifier/.venv/bin/python defence/e2e/e2e_client.py \
        --fw express --verifier 127.0.0.1:19111 --db 127.0.0.1:19112 --off 127.0.0.1:19113
"""
from __future__ import annotations

import argparse
import json
import socket
import urllib.request

from minter.dpop import headers_for

ORIGIN = "http://api.bench.test"


def verify(verifier, method, uri, auth):
    req = urllib.request.Request(f"http://{verifier}/authz/orig", method="GET")
    req.add_header("X-Original-Method", method)
    req.add_header("X-Original-URI", uri)
    req.add_header("X-Original-Host", "api.bench.test")
    for k, v in auth.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.headers.get("X-Verified-View")
    except urllib.error.HTTPError as e:
        return e.code, None


def raw(addr, method, target, headers, body=b""):
    host, port = addr.split(":")
    lines = [f"{method} {target} HTTP/1.1", "Host: api.bench.test", "Connection: close"]
    lines += [f"{k}: {v}" for k, v in headers]
    if body or method in ("POST", "PUT"):
        lines.append(f"Content-Length: {len(body)}")
    data = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body
    with socket.create_connection((host, int(port)), timeout=10) as s:
        s.sendall(data)
        buf = b""
        while chunk := s.recv(65536):
            buf += chunk
    head, _, rbody = buf.partition(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1])
    if b"transfer-encoding: chunked" in head.lower():
        out, rest = b"", rbody
        while rest:
            n, _, rest = rest.partition(b"\r\n")
            n = int(n, 16)
            if n == 0:
                break
            out, rest = out + rest[:n], rest[n + 2:]
        rbody = out
    try:
        return status, json.loads(rbody)
    except Exception:
        return status, {"raw": rbody.decode("latin-1")[:200]}


# (name, proof (htm, path), gateway view (method, uri), sent (method, target, extra headers, body), view header policy)
FORM = [("Content-Type", "application/x-www-form-urlencoded"), ("X-HTTP-Method-Override", "DELETE")]
CASES = [
    ("benign_get", ("GET", "/api/v1/accounts/acc-alice-1"), ("GET", "/api/v1/accounts/acc-alice-1"),
     ("GET", "/api/v1/accounts/acc-alice-1", [], b""), "one"),
    ("benign_v2_prefix", ("GET", "/api/v2/accounts/acc-alice-1"), ("GET", "/api/v2/accounts/acc-alice-1"),
     ("GET", "/api/v2/accounts/acc-alice-1", [], b""), "one"),
    ("g1_method_override", ("POST", "/api/v1/accounts/acc-alice-1"), ("POST", "/api/v1/accounts/acc-alice-1"),
     ("POST", "/api/v1/accounts/acc-alice-1", FORM, b"_method=DELETE"), "one"),
    ("g1_query_dispatch", ("POST", "/api/v1/accounts/acc-alice-1/actions"), ("POST", "/api/v1/accounts/acc-alice-1/actions?op=freeze"),
     ("POST", "/api/v1/accounts/acc-alice-1/actions?op=close", [], b""), "one"),
    ("header_lifted_to_other_id", ("GET", "/api/v1/accounts/acc-alice-1"), ("GET", "/api/v1/accounts/acc-alice-1"),
     ("GET", "/api/v1/accounts/acc-bob-1", [], b""), "one"),
    ("missing_view_header", ("GET", "/api/v1/me"), ("GET", "/api/v1/me"), ("GET", "/api/v1/me", [], b""), "none"),
    ("g3_duplicate_view_header", ("GET", "/api/v1/me"), ("GET", "/api/v1/me"), ("GET", "/api/v1/me", [], b""), "dup"),
]


def run_case(args, target_addr, case):
    name, (htm, ppath), (vm, vu), (sm, starget, extra, body), policy = case
    auth = headers_for("alice", htm, ORIGIN + ppath)
    vstatus, view = verify(args.verifier, vm, vu, auth)
    hdrs = [("Authorization", auth["Authorization"]), ("DPoP", auth["DPoP"])] + extra
    if policy == "one" and view:
        hdrs.append(("X-Verified-View", view))
    elif policy == "dup" and view:
        hdrs += [("X-Verified-View", view), ("X-Verified-View", view)]
    status, rbody = raw(target_addr, sm, starget, hdrs, body)
    return {"verifier_status": vstatus, "x_verified_view_sent": policy if view else "none",
            "status": status, "op_id": rbody.get("op_id"), "denied": rbody.get("denied", False),
            "reason": rbody.get("reason"), "method": rbody.get("method")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fw", required=True)
    ap.add_argument("--verifier", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--off", required=True)
    args = ap.parse_args()
    out = []
    for c in CASES:
        out.append({"case": c[0], "framework": args.fw, "defence_db": run_case(args, args.db, c),
                    "defence_off": run_case(args, args.off, c)})
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
