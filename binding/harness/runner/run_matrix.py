"""run_matrix.py — send mutation cases through a topology and record runner.jsonl.

Flow per case (CONTRACT §6):
  1. Mint a fresh token+proof bound to the BASE op canonical (htm, htu) for the client.
  2. Inject them into the case's raw bytes (replacing the @@AT@@/@@PROOF@@ placeholders).
  3. Send the EXACT bytes over a raw TCP socket (no HTTP-library normalisation).
  4. Record status/body/jti in harness/logs/<topology>/runner.jsonl.

Targeting:
  --topology <yaml>      : read id + host_port from a W6 topology file.
  --host-port <N>        : point at an already-running stack (no topology file needed).
  --direct               : ground-truth mode. Hits the executor directly (no gateway).
                           Use with --host-port = the executor's published port. By
                           default --direct runs ONLY the baseline (depth-0) cases, which
                           is exactly op(pi); pass --direct-all to send the full matrix.

Cases:
  --cases <jsonl>        : read pre-generated cases.
  (default)              : generate depth-1 cases in-process via mutator.compose.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
import time
from typing import Dict, Iterable, List, Optional

import yaml

from rawhttp.client import send as raw_send
from rawhttp.model import RawRequest
from mutator.base_ops import BASE_OPS_BY_ID, AUTHZ_PLACEHOLDER, PROOF_PLACEHOLDER
from mutator import compose
from runner.minter_adapter import get_minter

HARNESS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_ROOT = os.path.join(HARNESS_DIR, "logs")


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def load_cases(path: Optional[str]) -> List[dict]:
    if path:
        cases = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    cases.append(json.loads(line))
        return cases
    # default: generate depth-1 in-process
    return [json.loads(c.to_json()) for c in compose.generate(depth=1)]


def inject_auth(raw_b64: str, authz: str, proof: str) -> bytes:
    """Replace auth placeholders in the raw request bytes.

    `authz` is the full Authorization header value ("DPoP <at>")."""
    import base64
    raw = base64.b64decode(raw_b64)
    raw = raw.replace(AUTHZ_PLACEHOLDER.encode(), authz.encode())
    raw = raw.replace(PROOF_PLACEHOLDER.encode(), proof.encode())
    return raw


def parse_resp_op_id(body: bytes) -> Optional[str]:
    try:
        obj = json.loads(body.decode("utf-8"))
    except Exception:
        return None
    if isinstance(obj, dict):
        v = obj.get("op_id")
        return v if isinstance(v, str) else None
    return None


def run(cases: List[dict], *, host: str, port: int, mode: str, topology_id: str,
        out_path: str, minter_prefer: str = "auto", timeout: float = 10.0,
        limit: Optional[int] = None, delay: float = 0.0,
        verbose: bool = False) -> Dict[str, int]:
    minter = get_minter(prefer=minter_prefer)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    counts = {"sent": 0, "errors": 0}

    with open(out_path, "w") as out:
        for i, case in enumerate(cases):
            if limit is not None and i >= limit:
                break
            base_op = BASE_OPS_BY_ID.get(case["base_op_id"])
            if base_op is None:
                continue
            htm, htu = base_op.htm, base_op.htu
            client = case.get("client", "alice")
            try:
                authz, proof, jti = minter.mint(client=client, htm=htm, htu=htu)
            except Exception as e:
                rec = _error_record(case, mode, topology_id, host, port, htm, htu,
                                    minter.kind, f"mint-failed: {e}")
                out.write(json.dumps(rec) + "\n")
                counts["errors"] += 1
                continue

            raw = inject_auth(case["raw_request_b64"], authz, proof)
            resp = raw_send(host, port, raw, timeout=timeout)
            body_sha = hashlib.sha256(resp.body).hexdigest()
            rec = {
                "ts": _now_iso(),
                "case_id": case["case_id"],
                "base_op_id": case["base_op_id"],
                "base_method": case["base_method"],
                "base_path": case["base_path"],
                "primitive_ids": case.get("primitive_ids", []),
                "depth": case.get("depth", len(case.get("primitive_ids", []))),
                "groups": case.get("groups", []),
                "client": client,
                "jti": jti,
                "mode": mode,
                "topology": topology_id,
                "host": host,
                "host_port": port,
                "htm": htm,
                "htu": htu,
                "minter": minter.kind,
                "sent_bytes_len": len(raw),
                "status": resp.status,
                "resp_framing": resp.framing,
                "resp_body_len": len(resp.body),
                "resp_body_sha256": body_sha,
                "resp_op_id": parse_resp_op_id(resp.body),
                "error": resp.error,
            }
            out.write(json.dumps(rec) + "\n")
            counts["sent"] += 1
            if resp.error:
                counts["errors"] += 1
            if verbose:
                sys.stderr.write(f"[{i}] {case['case_id']} -> {resp.status} "
                                 f"op={rec['resp_op_id']} err={resp.error}\n")
            if delay:
                time.sleep(delay)
    return counts


def _error_record(case, mode, topology_id, host, port, htm, htu, minter_kind, error):
    return {
        "ts": _now_iso(), "case_id": case["case_id"], "base_op_id": case["base_op_id"],
        "base_method": case["base_method"], "base_path": case["base_path"],
        "primitive_ids": case.get("primitive_ids", []),
        "depth": case.get("depth", 0), "groups": case.get("groups", []),
        "client": case.get("client", "alice"), "jti": None, "mode": mode,
        "topology": topology_id, "host": host, "host_port": port, "htm": htm, "htu": htu,
        "minter": minter_kind, "sent_bytes_len": 0, "status": 0, "resp_framing": "none",
        "resp_body_len": 0, "resp_body_sha256": "", "resp_op_id": None, "error": error,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run the mutation matrix (CONTRACT §6).")
    tgt = ap.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--topology", help="W6 topology YAML (reads id + host_port).")
    tgt.add_argument("--host-port", type=int, help="port of an already-running stack.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--direct", action="store_true",
                    help="ground-truth mode: hit the executor directly (no gateway).")
    ap.add_argument("--direct-all", action="store_true",
                    help="with --direct, send the full matrix instead of only baselines.")
    ap.add_argument("--cases", help="pre-generated cases JSONL (default: generate depth-1).")
    ap.add_argument("--out", help="output runner.jsonl (default: logs/<id>/runner.jsonl).")
    ap.add_argument("--minter", default="auto", choices=["auto", "shim", "w3"])
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("--topology-id", default=None,
                    help="override log/topology id when using --host-port.")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    if args.topology:
        with open(args.topology) as f:
            topo = yaml.safe_load(f)
        topology_id = topo["id"]
        port = int(topo["host_port"])
    else:
        port = args.host_port
        topology_id = args.topology_id or (f"direct-{port}" if args.direct else f"adhoc-{port}")

    mode = "direct" if args.direct else "gateway"
    out_path = args.out or os.path.join(LOGS_ROOT, topology_id, "runner.jsonl")

    cases = load_cases(args.cases)
    if args.direct and not args.direct_all:
        cases = [c for c in cases if c.get("depth", len(c.get("primitive_ids", []))) == 0]
        if not cases:  # caller passed a file with no baselines; synthesize them
            cases = [json.loads(c.to_json())
                     for c in compose.generate(depth=1) if c.depth == 0]

    counts = run(cases, host=args.host, port=port, mode=mode, topology_id=topology_id,
                 out_path=out_path, minter_prefer=args.minter, timeout=args.timeout,
                 limit=args.limit, delay=args.delay, verbose=args.verbose)
    sys.stderr.write(f"runner[{topology_id}/{mode}] minter={args.minter} "
                     f"wrote {out_path}: {counts}\n")


if __name__ == "__main__":
    main()
