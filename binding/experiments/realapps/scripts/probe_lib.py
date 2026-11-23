"""Reusable probe harness for the W22 real-application study.

Mirrors the kill/probe_fragment.py and e4_runner approach, but the ORACLE is the real
application's own route match / access log (CONTRACT + task brief), not a bench executor
log. Every probe:

  1. mints a REAL DPoP proof (W3 minter) bound to a BASE op's canonical (htm, htu).
     htu = origin + base_path (no query, no fragment); host is always api.bench.test (CONTRACT §1).
  2. serialises an EXACT request line + headers + body (no HTTP-library normalisation) and
     sends it over a raw TCP socket to the gateway's host port (rawhttp.client.send).
  3. captures: response status/body, the verifier/PDP decision for this proof's jti
     (from verifier.jsonl), and the gateway + app container log lines emitted for THIS probe
     (docker logs --since t0; probes run strictly sequentially so the delta is this probe's).

Nothing is fabricated: the verifier decision and the app's log/response are recorded verbatim.
Classification into A_leak / A_client hits is done later against ground truth (direct-to-app).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

HARNESS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "harness"))
sys.path.insert(0, HARNESS)

from minter import dpop  # noqa: E402  (W3 real minter)
from rawhttp.client import send  # noqa: E402

ORIGIN = "http://api.bench.test"
HOST = "api.bench.test"


def mint(client: str, htm: str, base_path: str, variant: str = "valid"):
    """Return (authorization_value, dpop_proof, jti) bound to (htm, ORIGIN+base_path)."""
    htu = ORIGIN + base_path
    h = dpop.headers_for(client, htm, htu, variant=variant)
    proof = h["DPoP"]
    if isinstance(proof, list):
        proof = proof[0]
    _, claims = dpop.decode_unverified(proof)
    return h["Authorization"], proof, claims.get("jti")


def build_raw(method: str, target: str, headers: list[tuple[str, str]], body: bytes = b"") -> bytes:
    """Serialise exact request bytes. headers is an ordered list of (name, value)."""
    lines = [f"{method} {target} HTTP/1.1"]
    have = {n.lower() for n, _ in headers}
    hdrs = list(headers)
    if "host" not in have:
        hdrs.insert(0, ("Host", HOST))
    if body and "content-length" not in have:
        hdrs.append(("Content-Length", str(len(body))))
    if "connection" not in have:
        hdrs.append(("Connection", "close"))
    for n, v in hdrs:
        lines.append(f"{n}: {v}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
    return head + body


def _now_rfc3339() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f000Z")


def docker_logs_since(container: str, since: str, until: str) -> str:
    try:
        r = subprocess.run(["docker", "logs", "--since", since, "--until", until, container],
                           capture_output=True, timeout=15)
        return (r.stdout + b"\n" + r.stderr).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return f"<docker logs error: {e}>"


def read_verifier_record(path: str, jti: str) -> dict:
    if not jti or not os.path.exists(path):
        return {}
    rec = {}
    try:
        for line in open(path):
            line = line.strip()
            if not line:
                continue
            o = json.loads(line)
            if o.get("jti") == jti:
                rec = o  # keep the last (should be one)
    except Exception:  # noqa: BLE001
        pass
    return rec


def run_probe(p: dict, cfg: dict) -> dict:
    """Run one probe dict against the live topology described by cfg."""
    client = p.get("client", "alice")
    method = p.get("method", p["base_htm"])
    body = p.get("body", "")
    body_b = body.encode() if isinstance(body, str) else body
    authz, proof, jti = mint(client, p["base_htm"], p["base_path"], p.get("variant", "valid"))
    headers = [("Host", HOST), ("Authorization", authz), ("DPoP", proof)]
    for n, v in p.get("headers", []):
        headers.append((n, v))
    if body_b:
        ct = p.get("content_type", "application/json")
        headers.append(("Content-Type", ct))
    raw = build_raw(method, p["target"], headers, body_b)
    t0 = _now_rfc3339()
    r = send("127.0.0.1", cfg["port"], raw, timeout=cfg.get("timeout", 15))
    time.sleep(cfg.get("settle", 0.5))
    t1 = _now_rfc3339()
    vrec = read_verifier_record(cfg["verifier_log"], jti)
    gw_log = docker_logs_since(cfg["gateway_container"], t0, t1) if cfg.get("gateway_container") else ""
    app_log = docker_logs_since(cfg["app_container"], t0, t1) if cfg.get("app_container") else ""
    bodytext = r.body.decode("utf-8", "replace")
    rec = {
        "label": p["label"], "client": client,
        "base_htm": p["base_htm"], "base_path": p["base_path"],
        "method": method, "target": p["target"], "jti": jti,
        "status": r.status, "resp_len": len(r.body),
        "resp_sha16": hashlib.sha256(r.body).hexdigest()[:16],
        "resp_body": bodytext[:cfg.get("body_cap", 500)],
        "resp_ctype": next((v for n, v in r.headers if n.lower() == "content-type"), None),
        "verifier_decision": vrec.get("decision"),
        "verifier_reason": vrec.get("reason"),
        "verifier_view_uri": vrec.get("view_uri"),
        "verifier_sub": vrec.get("sub"),
        "gw_log": gw_log.strip()[:cfg.get("log_cap", 800)],
        "app_log": app_log.strip()[:cfg.get("log_cap", 1200)],
        "error": r.error,
    }
    if p.get("notes"):
        rec["notes"] = p["notes"]
    return rec


def run_spec(spec_path: str, out_path: str) -> list[dict]:
    spec = json.load(open(spec_path))
    cfg = {k: spec[k] for k in ("port", "verifier_log", "gateway_container", "app_container")
           if k in spec}
    for k in ("timeout", "settle", "body_cap", "log_cap"):
        if k in spec:
            cfg[k] = spec[k]
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    out = []
    with open(out_path, "w") as fh:
        for p in spec["probes"]:
            rec = run_probe(p, cfg)
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            print(f'{rec["label"]:28} {rec["method"]:6} {rec["target"][:52]:52} '
                  f'-> {rec["status"]} V={rec["verifier_decision"]} len={rec["resp_len"]}')
            out.append(rec)
    return out


if __name__ == "__main__":
    run_spec(sys.argv[1], sys.argv[2])
