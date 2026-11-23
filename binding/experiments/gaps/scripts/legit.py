"""W18 A1 legit-traffic false rejection for +query / +digest.
A LEGITIMATE client signs exactly what it sends: htu (+ its query verbatim for +query) and cdig =
Content-Digest(body) for +digest. Each request is expected to be accepted and to execute its own op.
False rejection = status >= 400 or a different op. Raw TCP, exact bytes (no client-side normalisation).
Usage: legit.py --port N --bind full|query|digest|query-digest --out legit.jsonl
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE)); sys.path.insert(0, str(HERE.parent))
os.environ.setdefault("BH_KEYS_DIR", str(HERE.parents[2] / "harness" / "keys"))
import ab_base  # noqa: E402,F401
from minter_ablate.dpop import mint_bound  # noqa: E402
from rawhttp.client import send  # noqa: E402
from runner.run_matrix import parse_resp_op_id  # noqa: E402

H = "http://api.bench.test"
ACT = "/api/v1/accounts/acc-alice-1/actions"
# (id, op, method, path, query, body, content-type, extra headers, chunked?)
REQS = [
    ("q-bench", "accountAction.freeze", "POST", ACT, "op=freeze", b"", None, [], False),
    ("q-two-sorted", "accountAction.freeze", "POST", ACT, "op=freeze&reason=x", b"", None, [], False),
    ("q-two-unsorted", "accountAction.freeze", "POST", ACT, "reason=x&op=freeze", b"", None, [], False),
    ("q-enc-unreserved", "listAccounts", "GET", "/api/v1/accounts", "owner=%7Ealice", b"", None, [], False),
    ("q-lower-hex", "listAccounts", "GET", "/api/v1/accounts", "name=caf%c3%a9", b"", None, [], False),
    ("q-upper-hex", "listAccounts", "GET", "/api/v1/accounts", "name=caf%C3%A9", b"", None, [], False),
    ("q-space-pct20", "listAccounts", "GET", "/api/v1/accounts", "q=a%20b", b"", None, [], False),
    ("q-space-plus", "listAccounts", "GET", "/api/v1/accounts", "q=a+b", b"", None, [], False),
    ("q-brackets", "listAccounts", "GET", "/api/v1/accounts", "filter%5Bstatus%5D=open&page=2", b"", None, [], False),
    ("q-dup", "listAccounts", "GET", "/api/v1/accounts", "tag=b&tag=a", b"", None, [], False),
    ("q-flag", "listAccounts", "GET", "/api/v1/accounts", "verbose", b"", None, [], False),
    ("q-many-unsorted", "listAccounts", "GET", "/api/v1/accounts", "z=1&m=2&a=3&limit=10", b"", None, [], False),
    ("b-json", "graphql.getProfile", "POST", "/api/v1/graphql", "",
     b'{"operationName":"getProfile","query":"query getProfile { me { id } }"}', "application/json", [], False),
    ("b-json-chunked", "graphql.getProfile", "POST", "/api/v1/graphql", "",
     b'{"operationName":"getProfile","query":"query getProfile { me { id } }"}', "application/json", [], True),
    ("b-transfer", "createTransfer", "POST", "/api/v1/transfers", "",
     b'{"from":"acc-alice-1","to":"acc-bob-1","amount":"1.00"}', "application/json", [], False),
    ("b-put", "updateAccount", "PUT", "/api/v1/accounts/acc-alice-1", "", b'{"nickname":"n"}', "application/json", [], False),
    ("b-empty-get", "me", "GET", "/api/v1/me", "", b"", None, [], False),
    ("b-delete", "deleteAccount", "DELETE", "/api/v1/accounts/acc-alice-1", "", b"", None, [], False),
]


def build(r, bind):
    rid, op, m, path, q, body, ct, extra, chunked = r
    a, p, jti, cd = mint_bound("alice", m, H + path, query=q, body=body,
                               bind_query="query" in bind, bind_digest="digest" in bind)
    tgt = path + ("?" + q if q else "")
    hs = [("Host", "api.bench.test"), ("Authorization", a), ("DPoP", p), ("Accept", "application/json")]
    if cd:
        hs.append(("Content-Digest", cd))
    if ct:
        hs.append(("Content-Type", ct))
    if chunked:
        hs.append(("Transfer-Encoding", "chunked"))
        wire = f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
    else:
        if body:
            hs.append(("Content-Length", str(len(body))))
        wire = body
    hs.append(("Connection", "close"))
    raw = f"{m} {tgt} HTTP/1.1\r\n".encode() + b"".join(f"{k}: {v}\r\n".encode() for k, v in hs) + b"\r\n" + wire
    return raw, jti


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True); ap.add_argument("--bind", required=True)
    ap.add_argument("--out", required=True); ap.add_argument("--label", default="")
    a = ap.parse_args()
    fr = 0
    with open(a.out, "w") as f:
        for r in REQS:
            raw, jti = build(r, a.bind)
            resp = send("127.0.0.1", a.port, raw, timeout=10)
            op = parse_resp_op_id(resp.body)
            ok = resp.status < 400 and op == r[1]
            fr += 0 if ok else 1
            f.write(json.dumps({"label": a.label, "bind": a.bind, "req": r[0], "expected_op": r[1], "jti": jti,
                                "status": resp.status, "resp_op_id": op, "ok": ok,
                                "body": resp.body[:200].decode("latin-1")}) + "\n")
    print(f"[legit] {a.label} bind={a.bind}: {len(REQS)} sent, false_reject={fr}")


if __name__ == "__main__":
    main()
