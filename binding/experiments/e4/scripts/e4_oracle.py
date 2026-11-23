"""e4_oracle.py — authorization-soundness oracle for E4 (task item 3).

An **authorization-soundness violation** is: the PDP ALLOWED the request (subject alice) AND
the executor acted on a resource or operation alice is NOT permitted — an admin* op, or a
non-alice account id (bob's) in the executed path params. It is detected from the logs:

  * PDP decision: verifier.jsonl (the PDP writes a verifier-format record whose ``decision``
    already folds proof-validity AND the path policy; ``sub`` is the token subject).
  * Executed op/resource: executor.jsonl (``op_id``, ``path_params``, ``status``, ``denied``).

Reuses the join + loaders from oracle.correlate (CONTRACT §6 / oracle_spec). Emits, per
topology: violations.jsonl, outcomes.csv (every case's outcome), and a summary row.

    python ../experiments/e4/scripts/e4_oracle.py --log-dir <dir> --topology <yaml> \
        [--summary-csv runs/summary.csv]

Run from binding/harness.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "harness"))

import yaml

from oracle.correlate import _read_jsonl, _index_by_jti

ADMIN_OPS = {"adminListUsers", "adminDeleteUser"}
ALICE_IDS = {"acc-alice-1"}
BOB_ID = "acc-bob-1"


def _decode(v: str) -> str:
    try:
        return urllib.parse.unquote(v)
    except Exception:
        return v


def forbidden_reason(op_id: str, path_params: dict):
    """Return (is_forbidden, kind, detail) from the executed record alone.

    Conservative (skeptical of harness artefacts): a 'bob' owner-crossing requires a path
    param whose DECODED value is EXACTLY bob's account id. A value that merely *contains*
    'acc-bob-1' as a substring (e.g. a %2F-mangled id 'acc-alice-1/../acc-bob-1' that the
    app would look up verbatim and find nothing) is NOT counted; it is reported as
    'allowed_other' instead."""
    if op_id in ADMIN_OPS:
        return True, "admin", op_id
    for k, v in (path_params or {}).items():
        if not isinstance(v, str):
            continue
        if _decode(v) == BOB_ID or v == BOB_ID:
            return True, "bob", f"{k}={v}"
    return False, None, None


def _id_is_alice(path_params: dict) -> bool:
    for v in (path_params or {}).values():
        if isinstance(v, str) and _decode(v) in ALICE_IDS:
            return True
    return False


def pdp_allowed_alice(verifier_recs):
    for vrec in verifier_recs:
        if vrec.get("decision") == "allow" and (vrec.get("sub") in (None, "alice") or
                                                 str(vrec.get("sub", "")).endswith("alice")):
            return True, vrec
    return False, None


def classify(runner_rec, verifier_recs, exec_recs, pdp_recs):
    """Return an outcome dict for one case."""
    allowed, vrec = pdp_allowed_alice(verifier_recs)
    pdp_rec = pdp_recs[0] if pdp_recs else {}
    # the single most relevant executor record: a successful, non-NOT_FOUND one if present
    xs_ok = [x for x in exec_recs if int(x.get("status", 0)) < 400
             and x.get("op_id") not in (None, "NOT_FOUND") and not x.get("denied", False)]
    x = xs_ok[0] if xs_ok else (exec_recs[0] if exec_recs else None)

    outcome = {
        "case_id": runner_rec.get("case_id"),
        "vector_id": runner_rec.get("vector_id"),
        "policy_scope": runner_rec.get("policy_scope"),
        "class": runner_rec.get("class"),
        "forbidden_kind_intended": runner_rec.get("forbidden_kind"),
        "forbidden_op_intended": runner_rec.get("forbidden_op"),
        "runner_status": runner_rec.get("status"),
        "pdp_decision": (vrec or {}).get("decision") if vrec else
                        (verifier_recs[0].get("decision") if verifier_recs else None),
        "pdp_reason": (verifier_recs[0].get("reason") if verifier_recs else None),
        "matched_rule": pdp_rec.get("matched_rule"),
        "exec_op_id": (x or {}).get("op_id"),
        "exec_status": (x or {}).get("status"),
        "exec_path_params": (x or {}).get("path_params"),
        "effective_method": (x or {}).get("effective_method"),
        "raw_target": (x or {}).get("raw_target"),
        "route_template": (x or {}).get("route_template"),
    }

    if not verifier_recs and not exec_recs:
        outcome["outcome"] = "no_records"
        return outcome, None

    if not allowed:
        # PDP (or proof) denied — the policy / verifier blocked it.
        reason = (verifier_recs[0].get("reason") if verifier_recs else "no_verifier_rec")
        if reason and ("htu" in str(reason) or "view" in str(reason)):
            outcome["outcome"] = "proof_rejected"   # gateway normalised before PDP, htu mismatch
        elif str(reason).startswith("policy_deny"):
            outcome["outcome"] = "pdp_denied"
        elif not verifier_recs:
            outcome["outcome"] = "gateway_blocked"   # gateway 4xx before PDP
        else:
            outcome["outcome"] = "pdp_denied"
        return outcome, None

    # PDP allowed. What did the executor do?
    if x is None:
        outcome["outcome"] = "allowed_not_executed"
        return outcome, None
    if int(x.get("status", 0)) >= 400 or x.get("op_id") in (None, "NOT_FOUND") or x.get("denied"):
        outcome["outcome"] = "exec_rejected"         # router/framework resisted (e.g. 404)
        return outcome, None

    forbidden, kind, detail = forbidden_reason(x.get("op_id"), x.get("path_params") or {})
    if forbidden:
        outcome["outcome"] = "VIOLATION"
        outcome["violation_kind"] = kind
        outcome["violation_detail"] = detail
        violation = {
            "topology": runner_rec.get("topology"),
            "case_id": runner_rec.get("case_id"),
            "vector_id": runner_rec.get("vector_id"),
            "jti": runner_rec.get("jti"),
            "class": runner_rec.get("class"),
            "policy_scope": runner_rec.get("policy_scope"),
            "matched_rule": pdp_rec.get("matched_rule"),
            "pdp_view_uri": (vrec or {}).get("view_uri"),
            "exec_op_id": x.get("op_id"),
            "exec_path_params": x.get("path_params"),
            "effective_method": x.get("effective_method"),
            "raw_target": x.get("raw_target"),
            "route_template": x.get("route_template"),
            "violation_kind": kind,
            "violation_detail": detail,
            "severity": "S1",
            "source": runner_rec.get("source"),
            "rerun": "pending",
        }
        return outcome, violation

    # executor acted on a non-forbidden resource. If it is alice's own id (or an id-less
    # op she is permitted) it is sound; otherwise it hit a non-owned, non-bob id (e.g. a
    # %2F-mangled string) — reported but not a clean owner-crossing violation.
    pp = x.get("path_params") or {}
    if not pp or _id_is_alice(pp):
        outcome["outcome"] = "allowed_sound"
    else:
        outcome["outcome"] = "allowed_other"
    return outcome, None


def correlate_e4(log_dir, topo):
    runner = _read_jsonl(os.path.join(log_dir, "runner.jsonl"))
    verifier = _read_jsonl(os.path.join(log_dir, "verifier.jsonl"))
    executor = _read_jsonl(os.path.join(log_dir, "executor.jsonl"))
    pdp = _read_jsonl(os.path.join(log_dir, "pdp.jsonl"))
    ver_by = _index_by_jti(verifier)
    exec_by = _index_by_jti(executor)
    pdp_by = _index_by_jti(pdp)

    outcomes, violations = [], []
    for r in runner:
        jti = r.get("jti")
        oc, v = classify(r, ver_by.get(jti, []), exec_by.get(jti, []), pdp_by.get(jti, []))
        oc["topology"] = topo.get("id")
        outcomes.append(oc)
        if v:
            violations.append(v)
    outcomes.sort(key=lambda o: o["case_id"])
    violations.sort(key=lambda v: v["case_id"])
    return outcomes, violations


def write_outputs(log_dir, topo, outcomes, violations, summary_csv=None):
    with open(os.path.join(log_dir, "violations.jsonl"), "w") as f:
        for v in violations:
            f.write(json.dumps(v, sort_keys=True) + "\n")
    cols = ["topology", "case_id", "vector_id", "policy_scope", "class", "outcome",
            "violation_kind", "forbidden_kind_intended", "pdp_decision", "pdp_reason",
            "matched_rule", "exec_op_id", "exec_status", "effective_method",
            "exec_path_params", "raw_target", "route_template"]
    with open(os.path.join(log_dir, "outcomes.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for o in outcomes:
            o = dict(o)
            o["exec_path_params"] = json.dumps(o.get("exec_path_params"))
            w.writerow(o)

    n_viol = len(violations)
    admin_v = sum(1 for v in violations if v["violation_kind"] == "admin")
    bob_v = sum(1 for v in violations if v["violation_kind"] == "bob")
    pdp_allow = sum(1 for o in outcomes if o.get("pdp_decision") == "allow")
    summary = {
        "topology": topo.get("id"), "gateway": topo.get("gateway"),
        "profile": topo.get("profile"), "framework": topo.get("framework"),
        "verifier_image": (topo.get("verifier") or {}).get("image"),
        "cases": len(outcomes), "pdp_allow": pdp_allow,
        "violations": n_viol, "admin": admin_v, "bob": bob_v,
        "vectors_hit": ",".join(sorted({v["vector_id"] for v in violations})),
    }
    if summary_csv:
        _append_summary(summary_csv, summary)
    return summary


SUMMARY_COLS = ["topology", "gateway", "profile", "framework", "verifier_image",
                "cases", "pdp_allow", "violations", "admin", "bob", "vectors_hit"]


def _append_summary(path, row):
    rows = {}
    if os.path.exists(path):
        with open(path) as f:
            for r in csv.DictReader(f):
                rows[r["topology"]] = r
    rows[row["topology"]] = {k: row.get(k) for k in SUMMARY_COLS}
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SUMMARY_COLS)
        w.writeheader()
        for tid in sorted(rows):
            w.writerow(rows[tid])


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-dir", required=True)
    ap.add_argument("--topology", required=True)
    ap.add_argument("--summary-csv")
    a = ap.parse_args(argv)
    topo = yaml.safe_load(open(a.topology))
    outcomes, violations = correlate_e4(a.log_dir, topo)
    summary = write_outputs(a.log_dir, topo, outcomes, violations, a.summary_csv)
    sys.stderr.write(f"e4_oracle[{summary['topology']}] {summary}\n")


if __name__ == "__main__":
    main()
