"""correlate.py — the binding oracle (implements oracle/oracle_spec.md, CONTRACT §6).

Joins runner/verifier/executor logs on the proof `jti`, applies the hit definition
(spec §4), assigns severity (§5), classifies the edge cases (§6/§7), raises the separate
G3 propagation predicate (§8), deduplicates into root-cause signatures (§9), and writes
hits.jsonl / propagation.jsonl / oracle_other.jsonl plus a summary.csv row (§11).

The oracle is a PURE function of its inputs: `correlate(...)` returns an `OracleResult`;
`hits.jsonl` is sorted by case_id so re-running over the same logs is byte-identical (§10).

Where oracle_spec.md and CONTRACT §6 differ, the spec wins (per W2's instruction). The two
deviations are: (1) resource-substitution hits (same op_id, different path_params) count as
S1; (2) G3 header spoofing without an op change is reported separately, not as a binding
hit, and verifier-bypass is class B0.
"""
from __future__ import annotations

import argparse
import csv
import dataclasses
import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ─────────────────────────── severity / op taxonomy (spec §5) ───────────────────

STATE_CHANGING_OPS = {
    "updateAccount", "deleteAccount", "createTransfer",
    "graphql.deleteProfile", "adminListUsers", "adminDeleteUser",
}
READ_OPS = {"listAccounts", "getAccount", "getAccountV2", "me", "graphql.getProfile"}
LOW_OPS = {"health", "publicFile"}
STATE_CHANGING_METHODS = {"PUT", "DELETE", "PATCH"}

# Normalised trust-header names that denote identity/certificate (S1) vs routing (S2).
IDENTITY_TRUST_PREFIXES = ("x-verified-", "x-client-cert", "client-cert",
                           "x-forwarded-client-cert", "x-auth-")
ROUTING_TRUST_PREFIXES = ("x-forwarded-", "x-original-")


def _is_state_changing_op(op_id: str) -> bool:
    return op_id in STATE_CHANGING_OPS or op_id.startswith("accountAction.")


def classify_severity(exec_rec: dict, deviation_kinds: List[str]) -> str:
    """Severity from the executed record (spec §5). First match wins."""
    op_id = exec_rec.get("op_id", "")
    eff = (exec_rec.get("effective_method") or "").upper()
    if eff in STATE_CHANGING_METHODS or _is_state_changing_op(op_id) or "resource" in deviation_kinds:
        return "S1"
    if op_id in LOW_OPS:
        return "S3"
    if op_id in READ_OPS:
        return "S2"
    # Unknown handler op that still executed: default to S2 (a read-equivalent surprise).
    return "S2"


# ─────────────────────────── ground truth (spec §2) ─────────────────────────────

@dataclass
class GroundTruth:
    """op(pi) per base op for one framework: op_id + path_params."""
    by_base: Dict[str, dict] = field(default_factory=dict)  # base_op_id -> {op_id, path_params, status}

    def op_of(self, base_op_id: str) -> Optional[dict]:
        return self.by_base.get(base_op_id)

    def is_conformant(self, base_op_id: str) -> Optional[bool]:
        gt = self.by_base.get(base_op_id)
        if gt is None:
            return None  # unknown
        return gt.get("op_id") == base_op_id and int(gt.get("status", 200)) < 400


def load_ground_truth(path: Optional[str]) -> GroundTruth:
    gt = GroundTruth()
    if not path or not os.path.exists(path):
        return gt
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            gt.by_base[rec["base_op_id"]] = {
                "op_id": rec.get("op_id"),
                "path_params": rec.get("path_params", {}),
                "status": rec.get("status", 200),
            }
    return gt


# ─────────────────────────── log loading ────────────────────────────────────────

def _read_jsonl(path: Optional[str]) -> List[dict]:
    if not path or not os.path.exists(path):
        return []
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def _index_by_jti(records: List[dict]) -> Dict[Optional[str], List[dict]]:
    idx: Dict[Optional[str], List[dict]] = {}
    for r in records:
        idx.setdefault(r.get("jti"), []).append(r)
    return idx


# ─────────────────────────── hit logic (spec §4) ────────────────────────────────

def is_accepted(placement: str, verifier_recs: List[dict], exec_rec: dict) -> bool:
    """Condition (A): the request was accepted for this executor record."""
    vs_allow = any(v.get("decision") == "allow" for v in verifier_recs)
    vs_deny = any(v.get("decision") == "deny" for v in verifier_recs)
    orig_allow = any(v.get("adapter") == "orig" and v.get("decision") == "allow"
                     for v in verifier_recs)
    not_denied = not exec_rec.get("denied", False)
    if placement == "edge":
        return vs_allow and not vs_deny
    if placement == "origin":
        if verifier_recs:
            return not_denied and orig_allow and not vs_deny
        # CONTRACT §6 fallback: no verifier record -> "executor not denied"
        return not_denied
    if placement == "both":
        return vs_allow and not vs_deny and not_denied
    return vs_allow and not_denied


def deviation_kinds(base_op_id: str, base_method: str, exec_rec: dict,
                    gt: Optional[dict]) -> List[str]:
    """Which views diverged (spec §4 'deviation kind')."""
    kinds = []
    eff = (exec_rec.get("effective_method") or "").upper()
    if eff and eff != (base_method or "").upper():
        kinds.append("method")
    gt_template = None
    if gt and gt.get("op_id"):
        # reconstruct template indirectly: compare op_id first for dispatch/route
        pass
    exec_op = exec_rec.get("op_id")
    if exec_op != base_op_id and exec_op != "NOT_FOUND":
        # same template+method but different op => dispatch; otherwise route
        if eff == (base_method or "").upper():
            kinds.append("dispatch")
        else:
            kinds.append("route")
    # resource substitution: same op_id, different path_params than ground truth
    if gt is not None and exec_op == base_op_id:
        gt_pp = gt.get("path_params") or {}
        exec_pp = exec_rec.get("path_params") or {}
        if gt_pp and exec_pp and gt_pp != exec_pp:
            kinds.append("resource")
    # de-dup preserve order
    seen = set()
    return [k for k in kinds if not (k in seen or seen.add(k))]


def hit_for_exec(base_op_id: str, base_method: str, placement: str,
                 verifier_recs: List[dict], exec_rec: dict,
                 gt: Optional[dict]) -> Optional[Tuple[List[str], str]]:
    """Return (deviation_kinds, severity) if exec_rec is a hit, else None (spec §4)."""
    # (C) succeeded
    if int(exec_rec.get("status", 0)) >= 400:
        return None
    exec_op = exec_rec.get("op_id")
    if exec_op == "NOT_FOUND" or exec_rec.get("denied", False):
        return None
    # (B) different operation OR resource substitution
    diff_op = exec_op not in (base_op_id, "NOT_FOUND")
    resource_sub = False
    if gt is not None and exec_op == base_op_id:
        gt_pp = gt.get("path_params") or {}
        exec_pp = exec_rec.get("path_params") or {}
        resource_sub = bool(gt_pp) and bool(exec_pp) and gt_pp != exec_pp
    if not (diff_op or resource_sub):
        return None
    # (A) accepted
    if not is_accepted(placement, verifier_recs, exec_rec):
        return None
    dk = deviation_kinds(base_op_id, base_method, exec_rec, gt)
    if resource_sub and "resource" not in dk:
        dk.append("resource")
    sev = classify_severity(exec_rec, dk)
    return dk, sev


# ─────────────────────────── G3 propagation (spec §8) ───────────────────────────

def _fold(name: str) -> str:
    return name.lower().replace("_", "-")


def propagation_findings(runner_rec: dict, exec_recs: List[dict],
                         primitive_catalogue: Dict[str, dict]) -> List[dict]:
    """Raise a propagation finding when a G3-injected trust header reaches the executor's
    trust_headers with its marker value (spec §8)."""
    findings = []
    g3_injections = []  # (normalised_name, marker_value)
    for pid in runner_rec.get("primitive_ids", []):
        prim = primitive_catalogue.get(pid)
        if not prim or not pid.startswith("g3-"):
            continue
        for step in prim.get("transform", []):
            args = step.get("args", {})
            name = args.get("name")
            if name:
                for vkey in ("value", "second"):
                    if args.get(vkey):
                        g3_injections.append((_fold(name), str(args[vkey])))
    if not g3_injections:
        return findings
    for x in exec_recs:
        th = x.get("trust_headers", {}) or {}
        folded_th = {_fold(k): v for k, v in th.items()}
        for inj_name, marker in g3_injections:
            for th_name, th_val in folded_th.items():
                if th_name == inj_name and marker and marker in str(th_val):
                    sev = "S1" if any(th_name.startswith(p) for p in IDENTITY_TRUST_PREFIXES) else "S2"
                    findings.append({
                        "case_id": runner_rec.get("case_id"),
                        "jti": runner_rec.get("jti"),
                        "injected_header": inj_name,
                        "observed_header": th_name,
                        "marker": marker,
                        "severity": sev,
                        "exec_op_id": x.get("op_id"),
                    })
    return findings


# ─────────────────────────── core correlate ─────────────────────────────────────

@dataclass
class OracleResult:
    topology: str
    hits: List[dict]
    propagation: List[dict]
    other: List[dict]          # B0, uncorrelated, orphan, not_executed, allowed_not_executed
    summary: dict


def correlate(*, runner: List[dict], verifier: List[dict], executor: List[dict],
              topo: dict, ground_truth: GroundTruth,
              primitive_catalogue: Optional[Dict[str, dict]] = None) -> OracleResult:
    primitive_catalogue = primitive_catalogue or {}
    topology_id = topo.get("id", "unknown")
    placement = topo.get("placement", "edge")
    gateway = topo.get("gateway", "unknown")
    profile = topo.get("profile", "unknown")
    framework = topo.get("framework", "unknown")
    override = topo.get("override", "off")
    vcfg = topo.get("verifier", {}) or {}
    canon = vcfg.get("canon", "rfc3986")

    ver_by_jti = _index_by_jti(verifier)
    exec_by_jti = _index_by_jti(executor)
    runner_jtis = {r.get("jti") for r in runner if r.get("jti")}

    hits: List[dict] = []
    propagation: List[dict] = []
    other: List[dict] = []
    accepted_count = 0
    nonconformant_ops = {b for b in ground_truth.by_base
                         if ground_truth.is_conformant(b) is False}

    for r in runner:
        base_op = r.get("base_op_id")
        jti = r.get("jti")
        if base_op in nonconformant_ops:
            other.append({"kind": "nonconformant", "case_id": r.get("case_id"),
                          "base_op_id": base_op, "topology": topology_id})
            continue
        if jti is None:
            other.append({"kind": "runner_no_jti", "case_id": r.get("case_id"),
                          "topology": topology_id})
            continue
        VS = ver_by_jti.get(jti, [])
        XS = exec_by_jti.get(jti, [])
        gt = ground_truth.op_of(base_op)

        # propagation predicate (independent of hit)
        propagation.extend(propagation_findings(r, XS, primitive_catalogue))

        if not XS:
            if VS and any(v.get("decision") == "allow" for v in VS):
                other.append({"kind": "allowed_not_executed", "case_id": r.get("case_id"),
                              "jti": jti, "topology": topology_id})
            else:
                other.append({"kind": "not_executed", "case_id": r.get("case_id"),
                              "jti": jti, "topology": topology_id})
            continue

        # verifier_bypass (B0): edge/both, executor ran but verifier never consulted
        if placement in ("edge", "both") and not VS:
            b0_sev = "S1"  # unknown op executed without authz; grade conservatively
            for x in XS:
                if int(x.get("status", 0)) < 400 and x.get("op_id") not in ("NOT_FOUND",):
                    b0_sev = classify_severity(x, [])
                    break
            other.append({"kind": "B0_verifier_bypass", "case_id": r.get("case_id"),
                          "jti": jti, "topology": topology_id, "severity": b0_sev,
                          "exec_op_ids": [x.get("op_id") for x in XS]})
            continue

        if any(v.get("decision") == "allow" for v in VS) or (placement == "origin"):
            accepted_count += 1

        multi_exec = len(XS) > 1
        best = None
        for x in XS:
            res = hit_for_exec(base_op, r.get("base_method", ""), placement, VS, x, gt)
            if res is not None:
                best = (x, res[0], res[1])
                break  # any qualifying record makes it a hit (spec §6 multi_exec)
        if best is None:
            continue
        x, dk, sev = best
        v0 = VS[0] if VS else {}
        cls = sorted({pid.split("-")[0] for pid in r.get("primitive_ids", [])})
        hit = {
            "case_id": r.get("case_id"),
            "jti": jti,
            "topology": topology_id,
            "base_op_id": base_op,
            "exec_op_id": x.get("op_id"),
            "base_path_params": (gt or {}).get("path_params", {}),
            "exec_path_params": x.get("path_params", {}),
            "primitive_ids": r.get("primitive_ids", []),
            "class": cls,
            "deviation_kinds": dk,
            "severity": sev,
            "view_method": v0.get("view_method"),
            "view_uri": v0.get("view_uri"),
            "raw_method": x.get("raw_method"),
            "effective_method": x.get("effective_method"),
            "raw_target": x.get("raw_target"),
            "route_template": x.get("route_template"),
            "status": x.get("status"),
            "multi_exec": multi_exec,
            "rerun": "pending",
        }
        hits.append(hit)

    # orphan verifier records (spec §6)
    for jti, recs in ver_by_jti.items():
        if jti is not None and jti not in runner_jtis:
            other.append({"kind": "orphan_verifier", "jti": jti, "topology": topology_id,
                          "count": len(recs)})
    # uncorrelated executor records (jti null)
    null_exec = exec_by_jti.get(None, [])
    if null_exec:
        other.append({"kind": "uncorrelated_exec", "topology": topology_id,
                      "count": len(null_exec)})

    # minimisation + signatures (spec §9)
    _mark_minimal(hits)
    for h in hits:
        h["signature"] = _signature(h, gateway, profile, placement, framework, override, canon)

    hits.sort(key=lambda h: h["case_id"])  # determinism (spec §10)
    propagation.sort(key=lambda p: (p.get("case_id") or "", p.get("observed_header") or ""))
    other.sort(key=lambda o: (o.get("kind", ""), str(o.get("case_id") or o.get("jti") or "")))

    sev_counts = {"S1": 0, "S2": 0, "S3": 0}
    for h in hits:
        sev_counts[h["severity"]] = sev_counts.get(h["severity"], 0) + 1
    signatures = {h["signature"] for h in hits if h.get("minimal")}
    max_res = _max_res_hat(runner, exec_by_jti, ver_by_jti, placement, ground_truth)
    b0 = sum(1 for o in other if o["kind"] == "B0_verifier_bypass")
    uncorrelated = sum(o.get("count", 0) for o in other if o["kind"] == "uncorrelated_exec")

    summary = {
        "topology": topology_id,
        "cases": len(runner),
        "accepted": accepted_count,
        "hits_raw": len(hits),
        "hits_confirmed": sum(1 for h in hits if h["rerun"] == "confirmed"),
        "S1": sev_counts["S1"], "S2": sev_counts["S2"], "S3": sev_counts["S3"],
        "signatures": len(signatures),
        "max_res_hat": max_res,
        "b0": b0,
        "propagation": len(propagation),
        "uncorrelated": uncorrelated,
    }
    return OracleResult(topology_id, hits, propagation, other, summary)


def _signature(hit: dict, gateway, profile, placement, framework, override, canon) -> str:
    prim_set = "+".join(sorted(hit.get("minimal_primitive_set", hit["primitive_ids"])))
    cls = "".join(hit["class"])
    dk = ",".join(sorted(hit["deviation_kinds"]))
    return f"{gateway}|{profile}|{placement}|{framework}|{override}|{canon}|{prim_set}|{cls}|{dk}"


def _mark_minimal(hits: List[dict]) -> None:
    """Fold a hit with primitive set P into one with P' ⊂ P on the same topology/base_op
    and deviation kinds (spec §9). Marks `minimal` and sets `minimal_primitive_set`."""
    groups: Dict[tuple, List[dict]] = {}
    for h in hits:
        key = (h["topology"], h["base_op_id"], tuple(sorted(h["deviation_kinds"])))
        groups.setdefault(key, []).append(h)
    for key, group in groups.items():
        sets = [(h, frozenset(h["primitive_ids"])) for h in group]
        for h, s in sets:
            minimal = True
            for h2, s2 in sets:
                if s2 < s:  # proper subset also a hit => h is not minimal
                    minimal = False
                    break
            h["minimal"] = minimal
            h["minimal_primitive_set"] = sorted(s)


def _max_res_hat(runner, exec_by_jti, ver_by_jti, placement, gt: GroundTruth) -> int:
    """res_hat per base op = |{op(pi)} ∪ {executed ops under accepted+success}| (spec §4)."""
    per_base: Dict[str, set] = {}
    for r in runner:
        base = r.get("base_op_id")
        jti = r.get("jti")
        per_base.setdefault(base, set())
        gtv = gt.op_of(base)
        if gtv and gtv.get("op_id"):
            per_base[base].add((gtv["op_id"], json.dumps(gtv.get("path_params", {}), sort_keys=True)))
        for x in exec_by_jti.get(jti, []):
            if int(x.get("status", 0)) >= 400 or x.get("op_id") == "NOT_FOUND":
                continue
            if not is_accepted(placement, ver_by_jti.get(jti, []), x):
                continue
            per_base[base].add((x.get("op_id"),
                                json.dumps(x.get("path_params", {}), sort_keys=True)))
    return max((len(v) for v in per_base.values()), default=0)


# ─────────────────────────── output / CLI ───────────────────────────────────────

def write_outputs(result: OracleResult, log_dir: str, summary_csv: Optional[str] = None) -> None:
    os.makedirs(log_dir, exist_ok=True)
    with open(os.path.join(log_dir, "hits.jsonl"), "w") as f:
        for h in result.hits:
            f.write(json.dumps(h, sort_keys=True) + "\n")
    with open(os.path.join(log_dir, "propagation.jsonl"), "w") as f:
        for p in result.propagation:
            f.write(json.dumps(p, sort_keys=True) + "\n")
    with open(os.path.join(log_dir, "oracle_other.jsonl"), "w") as f:
        for o in result.other:
            f.write(json.dumps(o, sort_keys=True) + "\n")
    if summary_csv:
        _append_summary_row(summary_csv, result.summary)


SUMMARY_COLUMNS = ["topology", "cases", "accepted", "hits_raw", "hits_confirmed",
                   "S1", "S2", "S3", "signatures", "max_res_hat", "b0",
                   "propagation", "uncorrelated"]


def _append_summary_row(path: str, row: dict) -> None:
    # Keep one row per topology; rewrite the file so repeated runs are idempotent.
    rows = {}
    if os.path.exists(path):
        with open(path) as f:
            for r in csv.DictReader(f):
                rows[r["topology"]] = r
    rows[row["topology"]] = {k: row.get(k) for k in SUMMARY_COLUMNS}
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SUMMARY_COLUMNS)
        w.writeheader()
        for tid in sorted(rows):
            w.writerow(rows[tid])


def _load_primitive_catalogue() -> Dict[str, dict]:
    try:
        from mutator.catalogue import load_catalogue, catalogue_by_id
        prims = load_catalogue()
        return {p.id: {"transform": p.transform, "class": p.group}
                for p in prims}
    except Exception:
        return {}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Binding oracle correlator (oracle_spec.md).")
    ap.add_argument("--log-dir", required=True,
                    help="harness/logs/<id>/ containing runner/verifier/executor jsonl.")
    ap.add_argument("--topology", help="topology YAML (for gateway/placement/framework).")
    ap.add_argument("--ground-truth", help="groundtruth/<framework>.jsonl.")
    ap.add_argument("--summary-csv", default=None,
                    help="path to append the per-topology summary row.")
    args = ap.parse_args(argv)

    import yaml
    runner = _read_jsonl(os.path.join(args.log_dir, "runner.jsonl"))
    verifier = _read_jsonl(os.path.join(args.log_dir, "verifier.jsonl"))
    executor = _read_jsonl(os.path.join(args.log_dir, "executor.jsonl"))
    if args.topology and os.path.exists(args.topology):
        with open(args.topology) as f:
            topo = yaml.safe_load(f)
    else:
        # infer minimal topo from runner records
        topo = {"id": os.path.basename(args.log_dir.rstrip("/")),
                "placement": "edge", "framework": "unknown"}
    gt = load_ground_truth(args.ground_truth)
    result = correlate(runner=runner, verifier=verifier, executor=executor,
                       topo=topo, ground_truth=gt,
                       primitive_catalogue=_load_primitive_catalogue())
    write_outputs(result, args.log_dir, summary_csv=args.summary_csv)
    import sys
    sys.stderr.write(f"oracle[{result.topology}] {result.summary}\n")


if __name__ == "__main__":
    main()
