#!/usr/bin/env python3
"""Framework-agnostic conformance test for bench-API executors (CONTRACT section 3).

Sends the canonical request for every op_id (plus query/body dispatch variants and NOT_FOUND
probes) directly to an executor, asserts the returned op_id, and checks that the executor wrote a
JSONL log line of the CONTRACT shape for each request, correlated by the DPoP `jti`.

Only the Python 3.12 standard library is used. Usage:

  python run_conformance.py http://127.0.0.1:18080 --docker-logs w4-fastapi
  python run_conformance.py http://127.0.0.1:18080 --log-file ./logs/executor.jsonl
  # extra sections (need the executor started with the matching env):
  ... --override on                      # OVERRIDE=on behaviour probes (informational)
  ... --verify-mode origin-raw --stub-log ./stub/verifier_stub.jsonl   # needs stub_verifier.py

Exit status 0 when every REQUIRED check passes. --json writes machine-readable results.
"""
from __future__ import annotations

import argparse
import base64
import http.client
import json
import subprocess
import sys
import time
import uuid
from urllib.parse import urlsplit

HOST = "api.bench.test"
LOG_FIELDS = {
    "ts": str, "framework": str, "jti": (str, type(None)), "op_id": str,
    "route_template": (str, type(None)), "raw_method": str, "effective_method": str,
    "raw_target": str, "path_params": dict, "query": str, "trust_headers": dict,
    "denied": bool, "status": int,
}


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def fake_dpop(jti: str) -> str:
    """Structurally valid but UNSIGNED proof: executors must read jti without verification."""
    h = b64u(json.dumps({"typ": "dpop+jwt", "alg": "ES256"}).encode())
    p = b64u(json.dumps({"jti": jti, "htm": "GET", "htu": "http://api.bench.test/", "iat": int(time.time())}).encode())
    return f"{h}.{p}.{b64u(b'not-a-signature')}"


# (name, method, target, body|None, content_type|None, expected op_id, expected status,
#  expected route_template, expected path_params)
ACC = "acc-alice-1"
CASES = [
    ("listAccounts", "GET", "/api/v1/accounts", None, None, "listAccounts", 200, "/api/v1/accounts", {}),
    ("getAccount", "GET", f"/api/v1/accounts/{ACC}", None, None, "getAccount", 200, "/api/v1/accounts/{id}", {"id": ACC}),
    ("updateAccount", "PUT", f"/api/v1/accounts/{ACC}", b'{"nickname":"x"}', "application/json", "updateAccount", 200, "/api/v1/accounts/{id}", {"id": ACC}),
    ("deleteAccount", "DELETE", f"/api/v1/accounts/{ACC}", None, None, "deleteAccount", 200, "/api/v1/accounts/{id}", {"id": ACC}),
    ("accountAction.freeze", "POST", f"/api/v1/accounts/{ACC}/actions?op=freeze", b"{}", "application/json", "accountAction.freeze", 200, "/api/v1/accounts/{id}/actions", {"id": ACC}),
    ("accountAction.close", "POST", f"/api/v1/accounts/{ACC}/actions?op=close", b"{}", "application/json", "accountAction.close", 200, "/api/v1/accounts/{id}/actions", {"id": ACC}),
    ("accountAction.unknown(op=bogus)", "POST", f"/api/v1/accounts/{ACC}/actions?op=bogus", b"{}", "application/json", "accountAction.unknown", 200, "/api/v1/accounts/{id}/actions", {"id": ACC}),
    ("accountAction.unknown(no op)", "POST", f"/api/v1/accounts/{ACC}/actions", b"{}", "application/json", "accountAction.unknown", 200, "/api/v1/accounts/{id}/actions", {"id": ACC}),
    ("createTransfer", "POST", "/api/v1/transfers", b'{"from":"acc-alice-1","to":"acc-bob-1","amount":"1.00"}', "application/json", "createTransfer", 200, "/api/v1/transfers", {}),
    ("graphql.getProfile", "POST", "/api/v1/graphql", b'{"operationName":"getProfile","query":"query getProfile { me { id } }"}', "application/json", "graphql.getProfile", 200, "/api/v1/graphql", {}),
    ("graphql.deleteProfile", "POST", "/api/v1/graphql", b'{"operationName":"deleteProfile","query":"mutation deleteProfile { deleteProfile }"}', "application/json", "graphql.deleteProfile", 200, "/api/v1/graphql", {}),
    ("graphql.unknown(other name)", "POST", "/api/v1/graphql", b'{"operationName":"somethingElse"}', "application/json", "graphql.unknown", 200, "/api/v1/graphql", {}),
    ("graphql.unknown(no name)", "POST", "/api/v1/graphql", b'{"query":"{ me { id } }"}', "application/json", "graphql.unknown", 200, "/api/v1/graphql", {}),
    ("graphql.unknown(bad json)", "POST", "/api/v1/graphql", b'{not json', "application/json", "graphql.unknown", 200, "/api/v1/graphql", {}),
    ("me", "GET", "/api/v1/me", None, None, "me", 200, "/api/v1/me", {}),
    ("adminListUsers", "GET", "/api/v1/admin/users", None, None, "adminListUsers", 200, "/api/v1/admin/users", {}),
    ("adminDeleteUser", "DELETE", "/api/v1/admin/users/u-123", None, None, "adminDeleteUser", 200, "/api/v1/admin/users/{id}", {"id": "u-123"}),
    ("health", "GET", "/api/v1/health", None, None, "health", 200, "/api/v1/health", {}),
    ("publicFile", "GET", "/api/v1/public/terms.txt", None, None, "publicFile", 200, "/api/v1/public/{file}", {"file": "terms.txt"}),
    ("getAccountV2", "GET", f"/api/v2/accounts/{ACC}", None, None, "getAccountV2", 200, "/api/v2/accounts/{id}", {"id": ACC}),
    ("NOT_FOUND(unknown path)", "GET", "/api/v1/does-not-exist", None, None, "NOT_FOUND", 404, None, {}),
    ("NOT_FOUND(method mismatch PATCH)", "PATCH", f"/api/v1/accounts/{ACC}", b"{}", "application/json", "NOT_FOUND", 404, None, {}),
    ("NOT_FOUND(v2 unknown)", "GET", "/api/v2/transfers", None, None, "NOT_FOUND", 404, None, {}),
]

# ─── W15 ext-routes: v2 route space (only present when the executor runs with ROUTES=v2) ───
# Appended to CASES when --v2 is given. postAccount/getStatements/catchAllFile/deleteStatement.
SID = "stmt-7"
V2_CASES = [
    ("postAccount", "POST", f"/api/v1/accounts/{ACC}", b"{}", "application/json", "postAccount", 200, "/api/v1/accounts/{id}", {"id": ACC}),
    ("getStatements", "GET", f"/api/v1/accounts/{ACC}/statements", None, None, "getStatements", 200, "/api/v1/accounts/{id}/statements", {"id": ACC}),
    ("deleteStatement", "DELETE", f"/api/v1/accounts/{ACC}/statements/{SID}", None, None, "deleteStatement", 200, "/api/v1/accounts/{id}/statements/{sid}", {"id": ACC, "sid": SID}),
    # Catch-all path_params differ by framework (Spring {*path} keeps a leading '/', others don't);
    # that differential is the point of this route, so op_id/status are asserted but params is not (None).
    ("catchAllFile(single)", "GET", "/api/v1/files/logo.png", None, None, "catchAllFile", 200, "/api/v1/files/{path}", None),
    ("catchAllFile(nested)", "GET", "/api/v1/files/a/b/c.txt", None, None, "catchAllFile", 200, "/api/v1/files/{path}", None),
    # method mismatch on a v2 path -> NOT_FOUND (statements is GET-only)
    ("NOT_FOUND(statements POST)", "POST", f"/api/v1/accounts/{ACC}/statements", b"{}", "application/json", "NOT_FOUND", 404, None, {}),
]

# OVERRIDE=on probes. Informational: support differs by framework by design (see READMEs).
OVERRIDE_PROBES = [
    ("header X-HTTP-Method-Override: DELETE", "POST", f"/api/v1/accounts/{ACC}", b"{}", "application/json",
     {"X-HTTP-Method-Override": "DELETE"}),
    ("query ?_method=DELETE", "POST", f"/api/v1/accounts/{ACC}?_method=DELETE", b"{}", "application/json", {}),
    ("form body _method=DELETE", "POST", f"/api/v1/accounts/{ACC}", b"_method=DELETE", "application/x-www-form-urlencoded", {}),
    ("header on GET (non-POST origin)", "GET", f"/api/v1/accounts/{ACC}", None, None,
     {"X-HTTP-Method-Override": "DELETE"}),
]


def send(base: str, method: str, target: str, body, ctype, extra=None, jti=None):
    u = urlsplit(base)
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=10)
    jti = jti or str(uuid.uuid4())
    headers = {"Host": HOST, "Authorization": "DPoP conformance-dummy-token", "DPoP": fake_dpop(jti),
               "Connection": "close"}
    if body is not None:
        headers["Content-Type"] = ctype
        headers["Content-Length"] = str(len(body))
    headers.update(extra or {})
    conn.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
    for k, v in headers.items():
        conn.putheader(k, v)
    conn.endheaders(body)
    r = conn.getresponse()
    raw = r.read()
    conn.close()
    try:
        js = json.loads(raw)
    except Exception:
        js = None
    return jti, r.status, js, raw


def read_logs(args) -> list[dict]:
    if args.log_file:
        text = open(args.log_file, encoding="utf-8").read()
    elif args.docker_logs:
        text = subprocess.run(["docker", "logs", args.docker_logs], capture_output=True, text=True).stdout
    else:
        return []
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def check_shape(rec: dict) -> list[str]:
    errs = []
    for k, t in LOG_FIELDS.items():
        if k not in rec:
            errs.append(f"missing field {k}")
        elif not isinstance(rec[k], t) or (t is int and isinstance(rec[k], bool)):
            errs.append(f"field {k} has type {type(rec[k]).__name__}")
    extra = set(rec) - set(LOG_FIELDS)
    if extra:
        errs.append(f"unexpected fields {sorted(extra)}")
    for name in rec.get("trust_headers", {}) or {}:
        if name != name.lower():
            errs.append(f"trust header name not lower-case: {name}")
    return errs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("base_url")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--log-file", help="host path of the executor's /logs/executor.jsonl")
    g.add_argument("--docker-logs", metavar="CONTAINER", help="read the log lines from `docker logs CONTAINER`")
    ap.add_argument("--framework", help="expected framework tag in responses/logs")
    ap.add_argument("--v2", action="store_true", help="also test the ROUTES=v2 route space (W15 ext-routes)")
    ap.add_argument("--override", choices=["off", "on"], default=None, help="run OVERRIDE probes")
    ap.add_argument("--verify-mode", choices=["origin-raw", "origin-routed"], default=None)
    ap.add_argument("--stub-log", help="stub_verifier.py JSONL log (for --verify-mode)")
    ap.add_argument("--json", help="write results JSON here")
    args = ap.parse_args()

    results = {"base_url": args.base_url, "required": [], "override": [], "verify": [], "trust": None}
    sent = []
    fails = 0

    # wait for the executor (up to 30 s)
    for _ in range(60):
        try:
            send(args.base_url, "GET", "/api/v1/health", None, None)
            break
        except OSError:
            time.sleep(0.5)

    cases = CASES + (V2_CASES if args.v2 else [])
    for name, m, tgt, body, ct, exp_op, exp_st, tmpl, params in cases:
        jti, st, js, raw = send(args.base_url, m, tgt, body, ct)
        got_op = (js or {}).get("op_id")
        errs = []
        if st != exp_st:
            errs.append(f"status {st} != {exp_st}")
        if got_op != exp_op:
            errs.append(f"op_id {got_op!r} != {exp_op!r}")
        if exp_st == 200 and js is not None:
            for k in ("op_id", "framework", "method", "path_params"):
                if k not in js:
                    errs.append(f"response missing {k}")
            if js.get("method") not in (None, m):
                errs.append(f"response method {js.get('method')} != {m}")
            if params is not None and "path_params" in js and js["path_params"] != params:
                errs.append(f"response path_params {js['path_params']} != {params}")
            if args.framework and js.get("framework") != args.framework:
                errs.append(f"framework {js.get('framework')} != {args.framework}")
        sent.append((name, jti, m, tgt, exp_op, exp_st, tmpl, params))
        results["required"].append({"case": name, "method": m, "target": tgt, "status": st, "op_id": got_op,
                                    "ok": not errs, "errors": errs})

    # trust-header capture (required)
    tjti, tst, tjs, _ = send(args.base_url, "GET", "/api/v1/me", None, None,
                             {"X-Forwarded-For": "203.0.113.9", "X-Verified-Sub": "bob",
                              "X-Original-URI": "/api/v1/health", "X-Auth-User": "admin",
                              "X-Client-Cert": "MIIB...", "X-Unrelated": "ignore-me"})
    expected_trust = {"x-forwarded-for": "203.0.113.9", "x-verified-sub": "bob",
                      "x-original-uri": "/api/v1/health", "x-auth-user": "admin", "x-client-cert": "MIIB..."}

    # override probes (informational)
    if args.override:
        for name, m, tgt, body, ct, extra in OVERRIDE_PROBES:
            jti, st, js, _ = send(args.base_url, m, tgt, body, ct, extra)
            results["override"].append({"probe": name, "method": m, "target": tgt, "status": st,
                                        "op_id": (js or {}).get("op_id"), "jti": jti})

    # verify-mode probes: allowed request + denied request (stub denies jti starting with "deny-")
    if args.verify_mode:
        vcases = [("allow getAccount", "GET", f"/api/v1/accounts/{ACC}?x=1", None, None, {}, str(uuid.uuid4()),
                   200, "GET", f"/api/v1/accounts/{ACC}?x=1", f"/api/v1/accounts/{ACC}"),
                  ("deny deleteAccount", "DELETE", f"/api/v1/accounts/{ACC}", None, None, {}, "deny-" + str(uuid.uuid4()),
                   401, "DELETE", f"/api/v1/accounts/{ACC}", f"/api/v1/accounts/{ACC}")]
        if args.override == "on":
            vcases.append(("allow override POST->DELETE", "POST", f"/api/v1/accounts/{ACC}", b"{}", "application/json",
                           {"X-HTTP-Method-Override": "DELETE"}, str(uuid.uuid4()), None, None,
                           f"/api/v1/accounts/{ACC}", f"/api/v1/accounts/{ACC}"))
        time.sleep(0.3)
        for name, m, tgt, body, ct, extra, jti, exp_st, raw_m, raw_u, routed_u in vcases:
            _, st, js, _ = send(args.base_url, m, tgt, body, ct, extra, jti=jti)
            time.sleep(0.2)
            views = []
            if args.stub_log:
                for line in open(args.stub_log, encoding="utf-8"):
                    rec = json.loads(line)
                    if rec.get("jti") == jti:
                        views.append(rec)
            errs = []
            if exp_st is not None and st != exp_st:
                errs.append(f"status {st} != {exp_st}")
            if len(views) != 1:
                errs.append(f"verifier called {len(views)} times")
            else:
                v = views[0]
                op = (js or {}).get("op_id")
                if args.verify_mode == "origin-raw":
                    exp_vm, exp_vu = (raw_m or m), raw_u
                else:
                    exp_vm = (js or {}).get("method") if st == 200 else (raw_m or m)
                    exp_vu = routed_u
                if v["x_original_method"] != exp_vm:
                    errs.append(f"X-Original-Method {v['x_original_method']!r} != {exp_vm!r}")
                if v["x_original_uri"] != exp_vu:
                    errs.append(f"X-Original-URI {v['x_original_uri']!r} != {exp_vu!r}")
                if v["x_original_host"] != HOST:
                    errs.append(f"X-Original-Host {v['x_original_host']!r}")
                if not v.get("dpop") or not v.get("authorization"):
                    errs.append("Authorization/DPoP not forwarded")
                views[0]["executor_op_id"] = op
            results["verify"].append({"case": name, "status": st, "op_id": (js or {}).get("op_id"),
                                      "view": views[0] if len(views) == 1 else None, "ok": not errs, "errors": errs})

    # log checks
    time.sleep(0.5)
    logs = read_logs(args)
    by_jti = {}
    for rec in logs:
        by_jti.setdefault(rec.get("jti"), []).append(rec)
    log_checked = bool(args.log_file or args.docker_logs)
    if log_checked:
        for res, (name, jti, m, tgt, exp_op, exp_st, tmpl, params) in zip(results["required"], sent):
            recs = by_jti.get(jti, [])
            errs = []
            if len(recs) != 1:
                errs.append(f"{len(recs)} log lines for jti")
            else:
                r = recs[0]
                errs += check_shape(r)
                expect = {"op_id": exp_op, "status": exp_st, "raw_method": m, "effective_method": m,
                          "raw_target": tgt, "query": tgt.partition("?")[2], "denied": False}
                if exp_op != "NOT_FOUND":
                    expect.update(route_template=tmpl)
                    if params is not None:
                        expect.update(path_params=params)
                else:
                    expect.update(route_template=None)
                for k, v in expect.items():
                    if r.get(k) != v:
                        errs.append(f"log {k}={r.get(k)!r} != {v!r}")
                if args.framework and r.get("framework") != args.framework:
                    errs.append(f"log framework {r.get('framework')!r}")
            res["log_ok"] = not errs
            res["log_errors"] = errs
            if errs:
                res["ok"] = False
        trecs = by_jti.get(tjti, [])
        terr = []
        if len(trecs) != 1:
            terr.append(f"{len(trecs)} log lines")
        else:
            th = trecs[0]["trust_headers"]
            if th != expected_trust:
                terr.append(f"trust_headers {th} != {expected_trust}")
        results["trust"] = {"status": tst, "ok": not terr, "errors": terr}
        # jti=null on a request without DPoP
        u = urlsplit(args.base_url)
        c = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=10)
        c.request("GET", "/api/v1/health?nodpop=" + uuid.uuid4().hex, headers={"Host": HOST})
        c.getresponse().read()
        c.close()
        time.sleep(0.3)
        tail = [r for r in read_logs(args) if r.get("raw_target", "").startswith("/api/v1/health?nodpop=")]
        results["jti_null"] = {"ok": bool(tail) and tail[-1].get("jti") is None}
        for res in results["verify"]:
            pass
        if args.verify_mode:
            for res, vc in zip(results["verify"], vcases):
                recs = by_jti.get(vc[6], [])
                if len(recs) == 1 and vc[7] == 401 and not recs[0].get("denied"):
                    res["ok"] = False
                    res["errors"].append("log denied != true")
                if len(recs) == 1 and vc[7] == 401 and recs[0].get("status") != 401:
                    res["ok"] = False
                    res["errors"].append(f"log status {recs[0].get('status')}")

    # report
    print(f"# conformance: {args.base_url}")
    for r in results["required"]:
        flag = "PASS" if r["ok"] else "FAIL"
        fails += not r["ok"]
        detail = "; ".join(r["errors"] + r.get("log_errors", []))
        print(f"{flag}  {r['case']:<36} {r['method']:<6} {r['target']:<48} -> {r['status']} {r['op_id']}  {detail}")
    if log_checked:
        t = results["trust"]
        fails += not t["ok"]
        print(f"{'PASS' if t['ok'] else 'FAIL'}  trust-header capture  {'; '.join(t['errors'])}")
        fails += not results["jti_null"]["ok"]
        print(f"{'PASS' if results['jti_null']['ok'] else 'FAIL'}  jti=null without DPoP header")
    else:
        print("NOTE  log checks skipped (no --log-file / --docker-logs)")
    for r in results["override"]:
        print(f"INFO  override: {r['probe']:<36} {r['method']} {r['target']} -> {r['status']} {r['op_id']}")
    for r in results["verify"]:
        fails += not r["ok"]
        v = r["view"] or {}
        print(f"{'PASS' if r['ok'] else 'FAIL'}  verify[{args.verify_mode}] {r['case']:<30} -> {r['status']} {r['op_id']} "
              f"view=({v.get('x_original_method')} {v.get('x_original_uri')})  {'; '.join(r['errors'])}")
    total = len(results["required"]) + (2 if log_checked else 0) + len(results["verify"])
    print(f"# {total - fails}/{total} required checks passed")
    results["passed"] = total - fails
    results["total"] = total
    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
