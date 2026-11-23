"""Determinism check: compare replication 2 (runs_rep2/) with replication 1 (runs/) per topology.
A_leak: set of (case_id, exec_op_id) in hits.jsonl. E4: set of (case_id, violation_kind) in violations.jsonl.
Writes analysis/rep2_compare.csv and analysis/rep2_compare.md."""
import csv, glob, json, os
D = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def keyset(d):
    for name, k2 in (("hits.jsonl", "exec_op_id"), ("violations.jsonl", "violation_kind")):
        p = os.path.join(d, name)
        if os.path.exists(p):
            return name, {(r["case_id"], r.get(k2)) for r in (json.loads(l) for l in open(p) if l.strip())}
    return None, None

rows = []
for d2 in sorted(glob.glob(os.path.join(D, "runs_rep2", "*", "w17-*"))):
    rel = os.path.relpath(d2, os.path.join(D, "runs_rep2")); d1 = os.path.join(D, "runs", rel)
    k1, s1 = keyset(d1); k2, s2 = keyset(d2)
    st = open(os.path.join(d2, "status.txt")).read().strip() if os.path.exists(os.path.join(d2, "status.txt")) else "missing"
    up_fail = "UP FAILED" in st
    rows.append({"run": rel, "kind": (k1 or k2 or "?").split(".")[0], "rep1": len(s1) if s1 is not None else None,
                 "rep2": len(s2) if s2 is not None else None, "only_rep1": len(s1 - s2) if s1 is not None and s2 is not None else None,
                 "only_rep2": len(s2 - s1) if s1 is not None and s2 is not None else None,
                 "identical": (s1 == s2) if s1 is not None and s2 is not None else False, "up_failed": up_fail})
with open(os.path.join(D, "analysis", "rep2_compare.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
n = len(rows); same = sum(r["identical"] for r in rows); fails = [r for r in rows if r["up_failed"]]
L = [f"Topologies replayed: {n}; identical hit/violation sets: {same}/{n}; up failures: {len(fails)}.", "",
     "| run | rep1 | rep2 | only rep1 | only rep2 |", "|---|---|---|---|---|"]
L += [f"| {r['run']} | {r['rep1']} | {r['rep2']} | {r['only_rep1']} | {r['only_rep2']} |" for r in rows if not r["identical"]]
if same == n: L.append("| (none differ) | | | | |")
open(os.path.join(D, "analysis", "rep2_compare.md"), "w").write("\n".join(L) + "\n")
print("\n".join(L))
