"""e4_runner.py — send the A_client attack battery through a running topology.

Per case (task E4 item 4): mint a fresh token + DPoP proof for client=alice bound to the
case's (htm, htu) where htu = the mutated URL, inject into the exact raw bytes, send over a
raw TCP socket, and record runner.jsonl (same schema the oracle expects, with the proof jti).

    python ../experiments/e4/scripts/e4_runner.py --topology <yaml> --cases <cases.jsonl>
    python ../experiments/e4/scripts/e4_runner.py --host-port 28500 --topology-id adhoc --cases ...

Run from binding/harness (so the harness packages import).
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "harness"))

import yaml

from rawhttp.client import send as raw_send
from mutator.base_ops import AUTHZ_PLACEHOLDER, PROOF_PLACEHOLDER
from runner.minter_adapter import get_minter

HARNESS_DIR = str(Path(__file__).resolve().parents[3] / "harness")
LOGS_ROOT = os.path.join(HARNESS_DIR, "logs")


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def inject_auth(raw_b64: str, authz: str, proof: str) -> bytes:
    raw = base64.b64decode(raw_b64)
    raw = raw.replace(AUTHZ_PLACEHOLDER.encode(), authz.encode())
    raw = raw.replace(PROOF_PLACEHOLDER.encode(), proof.encode())
    return raw


def parse_resp_op_id(body: bytes):
    try:
        obj = json.loads(body.decode("utf-8"))
    except Exception:
        return None
    return obj.get("op_id") if isinstance(obj, dict) else None


def load_cases(path: str):
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def run(cases, *, host, port, topology_id, out_path, minter_prefer="auto", timeout=10.0,
        delay=0.0, verbose=False):
    minter = get_minter(prefer=minter_prefer)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    counts = {"sent": 0, "errors": 0}
    with open(out_path, "w") as out:
        for i, case in enumerate(cases):
            htm, htu = case["htm"], case["htu"]
            client = case.get("client", "alice")
            try:
                authz, proof, jti = minter.mint(client=client, htm=htm, htu=htu)
            except Exception as e:
                out.write(json.dumps({
                    "ts": _now_iso(), "case_id": case["case_id"], "base_op_id": case["base_op_id"],
                    "base_method": case["base_method"], "base_path": case["base_path"],
                    "primitive_ids": case.get("primitive_ids", []), "client": client, "jti": None,
                    "topology": topology_id, "htm": htm, "htu": htu, "status": 0,
                    "error": f"mint-failed: {e}", "forbidden_op": case.get("forbidden_op"),
                    "forbidden_kind": case.get("forbidden_kind"),
                    "policy_scope": case.get("policy_scope"), "vector_id": case.get("vector_id"),
                    "class": case.get("class"), "source": case.get("source"),
                }) + "\n")
                counts["errors"] += 1
                continue
            raw = inject_auth(case["raw_request_b64"], authz, proof)
            resp = raw_send(host, port, raw, timeout=timeout)
            rec = {
                "ts": _now_iso(), "case_id": case["case_id"], "base_op_id": case["base_op_id"],
                "base_method": case["base_method"], "base_path": case["base_path"],
                "primitive_ids": case.get("primitive_ids", []), "depth": 1,
                "client": client, "jti": jti, "topology": topology_id,
                "host": host, "host_port": port, "htm": htm, "htu": htu,
                "minter": minter.kind, "sent_bytes_len": len(raw),
                "status": resp.status, "resp_framing": resp.framing,
                "resp_body_len": len(resp.body),
                "resp_body_sha256": hashlib.sha256(resp.body).hexdigest(),
                "resp_op_id": parse_resp_op_id(resp.body), "error": resp.error,
                # E4 metadata (carried for the oracle / report)
                "forbidden_op": case.get("forbidden_op"),
                "forbidden_kind": case.get("forbidden_kind"),
                "policy_scope": case.get("policy_scope"),
                "vector_id": case.get("vector_id"), "class": case.get("class"),
                "source": case.get("source"),
            }
            out.write(json.dumps(rec) + "\n")
            counts["sent"] += 1
            if resp.error:
                counts["errors"] += 1
            if verbose:
                sys.stderr.write(f"[{i}] {case['case_id']:24s} -> {resp.status} "
                                 f"op={rec['resp_op_id']} err={resp.error}\n")
            if delay:
                time.sleep(delay)
    return counts


def main(argv=None):
    ap = argparse.ArgumentParser()
    tgt = ap.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--topology")
    tgt.add_argument("--host-port", type=int)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--cases", required=True)
    ap.add_argument("--out")
    ap.add_argument("--topology-id")
    ap.add_argument("--minter", default="auto", choices=["auto", "shim", "w3"])
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args(argv)

    if a.topology:
        topo = yaml.safe_load(open(a.topology))
        topology_id = topo["id"]
        port = int(topo["host_port"])
    else:
        port = a.host_port
        topology_id = a.topology_id or f"adhoc-{port}"
    out_path = a.out or os.path.join(LOGS_ROOT, topology_id, "runner.jsonl")
    cases = load_cases(a.cases)
    counts = run(cases, host=a.host, port=port, topology_id=topology_id, out_path=out_path,
                 minter_prefer=a.minter, timeout=a.timeout, delay=a.delay, verbose=a.verbose)
    sys.stderr.write(f"e4_runner[{topology_id}] wrote {out_path}: {counts}\n")


if __name__ == "__main__":
    main()
