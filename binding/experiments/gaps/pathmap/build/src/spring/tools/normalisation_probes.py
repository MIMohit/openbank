#!/usr/bin/env python3
"""Raw-socket router-normalisation and override probes for one running executor (W5).

Sends each request as exact bytes (no HTTP library normalisation) and records status, op_id,
path_params and effective method. Output: a Markdown table on stdout and --json results.

  python3 normalisation_probes.py 127.0.0.1 18580 --json out.json --label "spring OVERRIDE=on"
"""
import argparse
import json
import socket

ACC = "acc-alice-1"
FORM = "application/x-www-form-urlencoded"
JSONCT = "application/json"

# (id, description, method, target, extra headers, body, content-type)
PROBES = [
    ("canon", "canonical getAccount", "GET", f"/api/v1/accounts/{ACC}", {}, None, None),
    # --- path normalisation
    ("enc-slash", "%2F inside {id}", "GET", "/api/v1/accounts/acc%2Falice", {}, None, None),
    ("enc-slash-lc", "%2f inside {id}", "GET", "/api/v1/accounts/acc%2falice", {}, None, None),
    ("enc-unreserved", "%61 (a) in a literal segment", "GET", f"/api/v1/%61ccounts/{ACC}", {}, None, None),
    ("enc-id", "%2D in {id}", "GET", "/api/v1/accounts/acc%2Dalice-1", {}, None, None),
    ("dot-seg", "/../ dot segment", "GET", f"/api/v1/admin/../accounts/{ACC}", {}, None, None),
    ("dot-seg-enc", "%2e%2e dot segment", "GET", f"/api/v1/admin/%2e%2e/accounts/{ACC}", {}, None, None),
    ("dot-single", "/./ segment", "GET", f"/api/v1/./accounts/{ACC}", {}, None, None),
    ("matrix-lit", ";x=1 on a literal segment", "GET", f"/api/v1/accounts;x=1/{ACC}", {}, None, None),
    ("matrix-var", ";x=1 on {id}", "GET", f"/api/v1/accounts/{ACC};x=1", {}, None, None),
    ("matrix-admin", ";x on admin segment (DELETE)", "DELETE", "/api/v1/admin;x=1/users/u-1", {}, None, None),
    ("trail-coll", "trailing slash on collection", "GET", "/api/v1/accounts/", {}, None, None),
    ("trail-item", "trailing slash on item", "GET", f"/api/v1/accounts/{ACC}/", {}, None, None),
    ("dbl-mid", "double slash mid-path", "GET", f"/api/v1//accounts/{ACC}", {}, None, None),
    ("dbl-lead", "double leading slash", "GET", "//api/v1/accounts", {}, None, None),
    ("case-lit", "upper-case literal segment", "GET", "/api/v1/ACCOUNTS", {}, None, None),
    ("case-prefix", "upper-case /API prefix", "GET", "/API/v1/accounts", {}, None, None),
    ("suffix", ".json suffix on {id}", "GET", f"/api/v1/accounts/{ACC}.json", {}, None, None),
    ("suffix-coll", ".json suffix on collection", "GET", "/api/v1/accounts.json", {}, None, None),
    ("backslash", "backslash separator", "GET", "/api/v1\\accounts", {}, None, None),
    ("enc-backslash", "%5C separator", "GET", "/api/v1%5Caccounts", {}, None, None),
    ("enc-qmark", "%3F inside {id}", "GET", "/api/v1/accounts/acc%3Fx", {}, None, None),
    ("nul", "%00 inside {id}", "GET", "/api/v1/accounts/acc%00x", {}, None, None),
    ("fragment", "#fragment in target", "GET", "/api/v1/me#frag", {}, None, None),
    ("abs-form", "absolute-form request-target", "GET", "http://api.bench.test/api/v1/me", {}, None, None),
    ("v2-prefix", "v2 prefix mount", "GET", f"/api/v2/accounts/{ACC}", {}, None, None),
    ("v2-dotdot", "v2 prefix then ../ into v1 admin", "GET", "/api/v2/../v1/admin/users", {}, None, None),
    ("v2-dbl", "double slash after v2 mount", "GET", f"/api/v2//accounts/{ACC}", {}, None, None),
    ("v2-case", "upper-case V2 mount", "GET", f"/api/V2/accounts/{ACC}", {}, None, None),
    # --- method handling
    ("method-lc", "lower-case method token", "get", f"/api/v1/accounts/{ACC}", {}, None, None),
    ("head", "HEAD on GET route", "HEAD", f"/api/v1/accounts/{ACC}", {}, None, None),
    ("options", "OPTIONS on item", "OPTIONS", f"/api/v1/accounts/{ACC}", {}, None, None),
    # --- G1 query / body dispatch semantics
    ("op-dup-fc", "?op=freeze&op=close", "POST", f"/api/v1/accounts/{ACC}/actions?op=freeze&op=close", {}, b"{}", JSONCT),
    ("op-dup-cf", "?op=close&op=freeze", "POST", f"/api/v1/accounts/{ACC}/actions?op=close&op=freeze", {}, b"{}", JSONCT),
    ("op-arr", "?op[]=close", "POST", f"/api/v1/accounts/{ACC}/actions?op[]=close", {}, b"{}", JSONCT),
    ("op-enc", "?%6Fp=close (encoded name)", "POST", f"/api/v1/accounts/{ACC}/actions?%6Fp=close", {}, b"{}", JSONCT),
    ("op-form", "op=close in form body, no query", "POST", f"/api/v1/accounts/{ACC}/actions", {}, b"op=close", FORM),
    ("op-form-vs-q", "?op=freeze + form body op=close", "POST", f"/api/v1/accounts/{ACC}/actions?op=freeze", {}, b"op=close", FORM),
    ("op-json", "op=close in JSON body, no query", "POST", f"/api/v1/accounts/{ACC}/actions", {}, b'{"op":"close"}', JSONCT),
    ("op-semicolon", "?x=1;op=close (; separator)", "POST", f"/api/v1/accounts/{ACC}/actions?x=1;op=close", {}, b"{}", JSONCT),
    ("gql-dupkey", "graphql duplicate operationName keys", "POST", "/api/v1/graphql", {},
     b'{"operationName":"getProfile","operationName":"deleteProfile"}', JSONCT),
    ("gql-text", "graphql JSON body sent as text/plain", "POST", "/api/v1/graphql", {}, b'{"operationName":"deleteProfile"}', "text/plain"),
    # --- method override (meaningful with OVERRIDE=on; with off they show the baseline)
    ("ov-hdr", "POST + X-HTTP-Method-Override: DELETE", "POST", f"/api/v1/accounts/{ACC}", {"X-HTTP-Method-Override": "DELETE"}, b"{}", JSONCT),
    ("ov-hdr-put", "POST + X-HTTP-Method-Override: PUT", "POST", f"/api/v1/accounts/{ACC}", {"X-HTTP-Method-Override": "PUT"}, b"{}", JSONCT),
    ("ov-hdr-get", "POST + X-HTTP-Method-Override: GET", "POST", f"/api/v1/accounts/{ACC}", {"X-HTTP-Method-Override": "GET"}, b"{}", JSONCT),
    ("ov-hdr-lc", "POST + X-HTTP-Method-Override: delete", "POST", f"/api/v1/accounts/{ACC}", {"X-HTTP-Method-Override": "delete"}, b"{}", JSONCT),
    ("ov-hdr-onget", "GET + X-HTTP-Method-Override: DELETE", "GET", f"/api/v1/accounts/{ACC}", {"X-HTTP-Method-Override": "DELETE"}, None, None),
    ("ov-hdr-onput", "PUT + X-HTTP-Method-Override: DELETE", "PUT", f"/api/v1/accounts/{ACC}", {"X-HTTP-Method-Override": "DELETE"}, b"{}", JSONCT),
    ("ov-xhm", "POST + X-HTTP-Method: DELETE", "POST", f"/api/v1/accounts/{ACC}", {"X-HTTP-Method": "DELETE"}, b"{}", JSONCT),
    ("ov-xmo", "POST + X-Method-Override: DELETE", "POST", f"/api/v1/accounts/{ACC}", {"X-Method-Override": "DELETE"}, b"{}", JSONCT),
    ("ov-q", "POST ?_method=DELETE", "POST", f"/api/v1/accounts/{ACC}?_method=DELETE", {}, b"{}", JSONCT),
    ("ov-form", "POST form _method=DELETE", "POST", f"/api/v1/accounts/{ACC}", {}, b"_method=DELETE", FORM),
    ("ov-form-lc", "POST form _method=delete", "POST", f"/api/v1/accounts/{ACC}", {}, b"_method=delete", FORM),
    ("ov-form-get", "POST form _method=GET", "POST", f"/api/v1/accounts/{ACC}", {}, b"_method=GET", FORM),
    ("ov-json", "POST JSON {\"_method\":\"DELETE\"}", "POST", f"/api/v1/accounts/{ACC}", {}, b'{"_method":"DELETE"}', JSONCT),
    ("ov-form-admin", "POST form _method=DELETE on admin user", "POST", "/api/v1/admin/users/u-1", {}, b"_method=DELETE", FORM),
    ("ov-hdr-admin", "POST + header DELETE on admin user", "POST", "/api/v1/admin/users/u-1", {"X-HTTP-Method-Override": "DELETE"}, b"{}", JSONCT),
    ("ov-both", "form _method=PUT + header DELETE", "POST", f"/api/v1/accounts/{ACC}", {"X-HTTP-Method-Override": "DELETE"}, b"_method=PUT", FORM),
]


def send(host, port, method, target, extra, body, ctype):
    lines = [f"{method} {target} HTTP/1.1", "Host: api.bench.test", "Connection: close",
             "Authorization: DPoP probe-token"]
    for k, v in extra.items():
        lines.append(f"{k}: {v}")
    if body is not None:
        lines.append(f"Content-Type: {ctype}")
        lines.append(f"Content-Length: {len(body)}")
    raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + (body or b"")
    s = socket.create_connection((host, port), timeout=15)
    s.sendall(raw)
    chunks = []
    while True:
        try:
            c = s.recv(65536)
        except socket.timeout:
            break
        if not c:
            break
        chunks.append(c)
    s.close()
    resp = b"".join(chunks)
    head, _, rbody = resp.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    try:
        status = int(status_line.split()[1])
    except Exception:
        status = None
    if b"transfer-encoding: chunked" in head.lower():
        out, rest = b"", rbody
        while rest:
            size_line, _, rest = rest.partition(b"\r\n")
            try:
                n = int(size_line.split(b";")[0], 16)
            except ValueError:
                break
            if n == 0:
                break
            out, rest = out + rest[:n], rest[n + 2:]
        rbody = out
    try:
        js = json.loads(rbody)
    except Exception:
        js = None
    return status, js, status_line


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--json")
    ap.add_argument("--label", default="")
    a = ap.parse_args()
    res = []
    for pid, desc, m, t, extra, body, ct in PROBES:
        try:
            st, js, sl = send(a.host, a.port, m, t, extra, body, ct)
        except Exception as e:
            st, js, sl = None, None, f"error: {e}"
        js = js if isinstance(js, dict) else {}
        res.append({"id": pid, "desc": desc, "method": m, "target": t, "headers": extra,
                    "body": body.decode() if body else None, "status": st, "status_line": sl,
                    "op_id": js.get("op_id"), "eff_method": js.get("method"),
                    "path_params": js.get("path_params")})
    print(f"### Probes: {a.label}\n")
    print("| id | request | status | op_id | effective method | path_params |")
    print("|---|---|---|---|---|---|")
    for r in res:
        req = f"`{r['method']} {r['target']}`" + (f" {r['headers']}" if r["headers"] else "") + \
              (f" body `{r['body']}`" if r["body"] else "")
        req = req.replace("|", "\\|")
        pp = json.dumps(r["path_params"]) if r["path_params"] else ""
        print(f"| {r['id']} | {req} | {r['status']} | {r['op_id'] or ''} | {r['eff_method'] or ''} | {pp.replace('|', '/')} |")
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"label": a.label, "results": res}, f, indent=2)


if __name__ == "__main__":
    main()
