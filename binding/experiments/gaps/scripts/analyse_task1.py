#!/usr/bin/env python3
"""W23 Task 1 analysis: 3x-rerun determinism for the swap / legit / E4-strict sets, and the sorted
QUERY_CANON attack-set result vs the shipped +query(rfc3986) runs. Reads only gaps/ outputs and the
ablation reference runs. Prints a summary and writes gaps/task1_summary.json."""
import json, pathlib, sys

G = pathlib.Path(__file__).resolve().parents[1]           # experiments/gaps
ABL = G.parent / "ablation"


def hitkey(h):
    return (h.get("case_id"), h.get("exec_op_id") or h.get("op_id"),
            json.dumps(h.get("exec_path_params") or h.get("path_params") or {}, sort_keys=True))


def hitset(p):
    p = pathlib.Path(p)
    return {hitkey(json.loads(l)) for l in p.open()} if p.exists() else None


def viol_set(p):
    p = pathlib.Path(p)
    if not p.exists():
        return None
    out = set()
    for l in p.open():
        v = json.loads(l)
        out.add((v.get("case_id"), v.get("exec_op_id") or v.get("op_id"),
                 json.dumps(v.get("exec_path_params") or {}, sort_keys=True)))
    return out


def ids(d):
    d = pathlib.Path(d)
    return sorted(x.name for x in d.iterdir()) if d.exists() else []


def determinism(label, repdirs, extract):
    """For every topology that appears in rep1, compare the extracted set across the 3 reps."""
    out = []
    base = pathlib.Path(repdirs[0])
    for tid in ids(base):
        sets = [extract(pathlib.Path(r) / tid) for r in repdirs]
        present = [s for s in sets if s is not None]
        confirmed = len(present) == len(repdirs) and all(s == present[0] for s in present)
        out.append({"topology": tid, "reps": len(present), "n": len(present[0]) if present else None,
                    "confirmed_3_3": confirmed,
                    "rep_sizes": [None if s is None else len(s) for s in sets]})
    return out


def main():
    summ = {}

    # ---- sorted attack set vs shipped +query(rfc3986) ----
    sorted_rows = []
    for tid in ids(G / "sorted" / "rep1"):
        reps = [hitset(G / "sorted" / f"rep{k}" / tid / "hits.jsonl") for k in (1, 2, 3)]
        present = [s for s in reps if s is not None]
        confirmed = len(present) == 3 and all(s == present[0] for s in present)
        # reference: shipped ablation +query run of the same framework/override
        ref_id = tid.replace("w23-query-sorted-", "w18-query-")
        ref = hitset(ABL / "runs" / ref_id / "hits.jsonl")
        same_as_query = (present and ref is not None and present[0] == ref)
        sorted_rows.append({"topology": tid, "sorted_hits": len(present[0]) if present else None,
                            "confirmed_3_3": confirmed, "ref_query_rfc3986": ref_id,
                            "query_hits": None if ref is None else len(ref),
                            "sorted_eq_query": bool(same_as_query)})
    summ["sorted"] = sorted_rows

    # ---- swap reruns ----
    summ["swap"] = determinism("swap", [G / "reruns" / "swap" / f"rep{k}" for k in (1, 2, 3)],
                               lambda d: hitset(d / "hits.jsonl"))

    # ---- legit reruns (compare false_reject counts across reps) ----
    legit_rows = []
    for tid in ids(G / "reruns" / "legit" / "rep1"):
        frs = []
        for k in (1, 2, 3):
            p = G / "reruns" / "legit" / f"rep{k}" / tid / "legit.jsonl"
            frs.append(sum(1 for l in p.open() if json.loads(l).get("false_reject")) if p.exists() else None)
        present = [x for x in frs if x is not None]
        legit_rows.append({"topology": tid, "false_reject_per_rep": frs,
                           "confirmed_3_3": len(present) == 3 and len(set(present)) == 1})
    summ["legit"] = legit_rows

    # ---- E4-strict reruns ----
    summ["e4_strict"] = determinism("e4", [G / "reruns" / "e4" / f"rep{k}" for k in (1, 2, 3)],
                                    lambda d: viol_set(d / "violations.jsonl"))

    (G / "task1_summary.json").write_text(json.dumps(summ, indent=1))

    # ---- print ----
    def tally(rows):
        return sum(1 for r in rows if r.get("confirmed_3_3")), len(rows)
    print("== SORTED attack set (QUERY_CANON=sorted) ==")
    sc = sum(1 for r in sorted_rows if r["sorted_eq_query"])
    print(f"  topologies: {len(sorted_rows)}; 3/3 confirmed: {sum(r['confirmed_3_3'] for r in sorted_rows)}; "
          f"sorted==+query(rfc3986) hit set: {sc}/{len(sorted_rows)}")
    for r in sorted_rows:
        print(f"   {r['topology']}: sorted={r['sorted_hits']} query={r['query_hits']} "
              f"eq={r['sorted_eq_query']} det={r['confirmed_3_3']}")
    for name in ("swap", "legit", "e4_strict"):
        c, n = tally(summ[name])
        print(f"== {name.upper()} reruns: {c}/{n} topologies confirmed 3/3 ==")
        for r in summ[name]:
            bad = "" if r["confirmed_3_3"] else "   <-- NOT 3/3"
            extra = r.get("false_reject_per_rep") or r.get("rep_sizes")
            print(f"   {r['topology']}: {extra} det={r['confirmed_3_3']}{bad}")


if __name__ == "__main__":
    main()
