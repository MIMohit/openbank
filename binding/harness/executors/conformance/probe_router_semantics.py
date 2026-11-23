#!/usr/bin/env python3
"""Raw-socket probe of an executor's path/method normalisation (README evidence, NOT pass/fail).

Sends each probe as exact bytes (no HTTP library normalisation) and prints status, op_id,
path_params and Location. Usage: python probe_router_semantics.py http://127.0.0.1:18080 [--json out.json]
"""
import argparse
import json
import socket
import sys
from urllib.parse import urlsplit

PROBES = [
    ("baseline", "GET", "/api/v1/accounts/acc-alice-1"),
    ("trailing slash (static)", "GET", "/api/v1/accounts/"),
    ("trailing slash (param)", "GET", "/api/v1/accounts/acc-alice-1/"),
    ("leading double slash", "GET", "//api/v1/me"),
    ("inner double slash", "GET", "/api//v1/me"),
    ("dot segment /./", "GET", "/api/v1/./me"),
    ("dot-dot segment", "GET", "/api/v1/x/../me"),
    ("encoded dot-dot %2e%2e", "GET", "/api/v1/x/%2e%2e/me"),
    ("upper-case path", "GET", "/API/V1/ME"),
    ("pct-encoded static char %6D", "GET", "/api/v1/%6De"),
    ("pct-encoded unreserved in param", "GET", "/api/v1/accounts/acc%2Dalice-1"),
    ("encoded slash in param %2F", "GET", "/api/v1/accounts/acc-alice-1%2Fx"),
    ("encoded slash public %2F", "GET", "/api/v1/public/a%2F..%2Fb"),
    ("matrix param on static ;x=1", "GET", "/api/v1/me;x=1"),
    ("matrix param on param ;x=1", "GET", "/api/v1/accounts/acc-alice-1;x=1"),
    ("utf-8 pct in param", "GET", "/api/v1/accounts/caf%C3%A9"),
    ("backslash", "GET", "/api/v1\\me"),
    ("v2 mount double slash", "GET", "/api/v2//accounts/acc-alice-1"),
    ("v2 mount trailing slash", "GET", "/api/v2/accounts/acc-alice-1/"),
    ("absolute-form target", "GET", "http://api.bench.test/api/v1/me"),
    ("HEAD on GET route", "HEAD", "/api/v1/me"),
    ("OPTIONS on GET route", "OPTIONS", "/api/v1/me"),
    ("lower-case method", "get", "/api/v1/me"),
    ("HPP op=freeze&op=close", "POST", "/api/v1/accounts/acc-alice-1/actions?op=freeze&op=close"),
    ("HPP op=close&op=freeze", "POST", "/api/v1/accounts/acc-alice-1/actions?op=close&op=freeze"),
    ("query ;-separated op", "POST", "/api/v1/accounts/acc-alice-1/actions?x=1;op=close"),
    ("query op[]=close", "POST", "/api/v1/accounts/acc-alice-1/actions?op[]=close"),
]


def raw(host, port, method, target, body=b""):
    req = (f"{method} {target} HTTP/1.1\r\nHost: api.bench.test\r\nConnection: close\r\n"
           f"Content-Length: {len(body)}\r\n" + ("Content-Type: application/json\r\n" if body else "")
           + "\r\n").encode("latin-1") + body
    s = socket.create_connection((host, port), timeout=5)
    s.sendall(req)
    data = b""
    while True:
        try:
            c = s.recv(65536)
        except socket.timeout:
            break
        if not c:
            break
        data += c
    s.close()
    head, _, rbody = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1]) if lines and len(lines[0].split()) > 1 else None
    hdrs = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
    try:
        js = json.loads(rbody)
    except Exception:
        js = None
    return status, hdrs, js


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base_url")
    ap.add_argument("--json")
    a = ap.parse_args()
    u = urlsplit(a.base_url)
    out = []
    for name, m, t in PROBES:
        body = b"{}" if m == "POST" else b""
        try:
            st, h, js = raw(u.hostname, u.port, m, t, body)
        except Exception as e:
            st, h, js = None, {}, {"error": str(e)}
        js = js if isinstance(js, dict) else {}
        rec = {"probe": name, "method": m, "target": t, "status": st, "op_id": js.get("op_id"),
               "path_params": js.get("path_params"), "location": h.get("location"), "allow": h.get("allow")}
        out.append(rec)
        extra = " ".join(f"{k}={rec[k]}" for k in ("path_params", "location", "allow") if rec[k])
        print(f"{name:<34} {m:<7} {t:<58} -> {st} {rec['op_id']} {extra}")
    if a.json:
        json.dump(out, open(a.json, "w"), indent=2)


if __name__ == "__main__":
    sys.exit(main())
