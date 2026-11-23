"""analyse_e4.py — aggregate all E4 runs into report-ready tables.

Reads experiments/e4/runs/*/violations.jsonl and outcomes.csv and emits:
  * analysis/violations_all.csv   one row per (topology, vector) violation
  * analysis/by_topology.csv      per-topology counts by kind
  * analysis/classes.json         the independent G2 authorization-soundness classes,
                                  attributed to the component that resolved the path:
                                    - "gateway": raw_target delivered to executor is ALREADY
                                      normalised (no '/../', no '//', no ';', etc.) => the
                                      gateway rewrote the upstream path but showed the PDP the
                                      raw one. Backend-independent.
                                    - "framework": raw_target still carries the mutation =>
                                      the gateway forwarded raw to BOTH and the framework/router
                                      resolved it. Backend-specific.
  * stdout: a human summary.

Run from binding/harness:  python ../experiments/e4/scripts/analyse_e4.py
"""
from __future__ import annotations
import csv, json, os, re, sys
from collections import defaultdict
from pathlib import Path

E4 = Path(__file__).resolve().parents[1]
RUNS = E4 / "runs"
ANA = E4 / "analysis"
ANA.mkdir(exist_ok=True)

# markers that, if ABSENT from the executor's raw_target, mean the gateway already
# normalised the path before proxying upstream (so the backend saw a clean path).
MUT = ["/../", "/%2e%2e/", "%2e%2e", "//", ";", "%2f", "%2F", "ADMIN", "API", ".json", "/.."]

def topo_meta(tid):
    # w12-<pol>-<gw3>-<fw>-<prof3>
    m = re.match(r"w12-(allow|block)-(\w{3})-(\w+)-(\w{3})$", tid)
    if not m: return {}
    gw = {"ngx":"nginx","trf":"traefik","env":"envoy","kng":"kong","apx":"apisix","hap":"haproxy"}[m.group(2)]
    prof = {"def":"default","rec":"recommended"}[m.group(4)]
    return {"policy": m.group(1), "gateway": gw, "framework": m.group(3), "profile": prof}

def resolved_by(v):
    """gateway (raw_target already clean) vs framework (raw_target still mutated)."""
    rt = v.get("raw_target") or ""
    view = v.get("pdp_view_uri") or ""
    # if the executor's raw target differs from the PDP view path and no mutation marker
    # remains in it, the gateway normalised upstream-only.
    had_mut = any(mk in view for mk in MUT)
    still_mut = any(mk in rt for mk in MUT)
    if had_mut and not still_mut:
        return "gateway"
    return "framework"

def main():
    rows = []
    for d in sorted(RUNS.iterdir()):
        if not d.is_dir(): continue
        vf = d / "violations.jsonl"
        if not vf.exists(): continue
        meta = topo_meta(d.name)
        for line in vf.read_text().splitlines():
            if not line.strip(): continue
            v = json.loads(line)
            rows.append({
                "topology": d.name, **meta,
                "vector_id": v.get("vector_id"), "class": v.get("class"),
                "violation_kind": v.get("violation_kind"),
                "exec_op_id": v.get("exec_op_id"),
                "exec_path_params": json.dumps(v.get("exec_path_params")),
                "effective_method": v.get("effective_method"),
                "route_template": v.get("route_template"),
                "pdp_view_uri": v.get("pdp_view_uri"),
                "raw_target": v.get("raw_target"),
                "matched_rule": v.get("matched_rule"),
                "resolved_by": resolved_by(v),
                "source": v.get("source"),
            })
    # violations_all.csv
    cols = ["topology","policy","gateway","framework","profile","vector_id","class",
            "violation_kind","exec_op_id","exec_path_params","effective_method",
            "route_template","resolved_by","matched_rule","pdp_view_uri","raw_target","source"]
    with open(ANA/"violations_all.csv","w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=cols,extrasaction="ignore"); w.writeheader()
        for r in rows: w.writerow(r)

    # by_topology
    bt=defaultdict(lambda: {"violations":0,"admin":0,"bob":0,"vectors":set(),"resolved_by":set()})
    for r in rows:
        b=bt[r["topology"]]; b["violations"]+=1
        b[r["violation_kind"]] = b.get(r["violation_kind"],0)+1
        b["vectors"].add(r["vector_id"]); b["resolved_by"].add(r["resolved_by"])
    with open(ANA/"by_topology.csv","w",newline="") as f:
        w=csv.writer(f); w.writerow(["topology","violations","admin","bob","resolved_by","vectors"])
        for t in sorted(bt):
            b=bt[t]; w.writerow([t,b["violations"],b.get("admin",0),b.get("bob",0),
                                 "|".join(sorted(b["resolved_by"])),",".join(sorted(b["vectors"]))])

    # mechanism (parsing differential) from the vector id prefix
    def mechanism(vid):
        if vid.startswith(("dotseg","encdotseg")): return "dot-segment"
        if vid.startswith("matrix"): return "matrix-param"
        if vid.startswith("dslash"): return "double-slash"
        if vid.startswith("json"): return "suffix-format(.json)"
        if vid.startswith("case"): return "case-fold"
        if vid.startswith("trail"): return "trailing-slash"
        if vid.startswith("encslash"): return "encoded-slash(%2F)"
        return vid

    # independent classes: group by (resolved_by component, mechanism). An independent
    # authorization-soundness class is a distinct (causing component, parsing differential).
    classes=defaultdict(lambda: {"topologies":set(),"gateways":set(),"frameworks":set(),
                                 "vectors":set(),"kinds":set(),"profiles":set(),"policies":set()})
    for r in rows:
        mech=mechanism(r["vector_id"])
        if r["resolved_by"]=="gateway":
            key=("gateway", r["gateway"], mech)     # component = the gateway
        else:
            key=("framework", r["framework"], mech) # component = the framework/router
        c=classes[key]
        c["topologies"].add(r["topology"]); c["gateways"].add(r["gateway"])
        c["frameworks"].add(r["framework"]); c["vectors"].add(r["vector_id"])
        c["kinds"].add(r["violation_kind"]); c["profiles"].add(r["profile"])
        c["policies"].add(r["policy"])
    out={}
    for (comp_kind,comp,mech),c in sorted(classes.items()):
        out[f"{comp_kind}:{comp}:{mech}"]={k:(sorted(v) if isinstance(v,set) else v) for k,v in c.items()}
    json.dump(out,open(ANA/"classes.json","w"),indent=2,sort_keys=True)

    # summary
    print(f"total violations: {len(rows)} across {len(bt)} topologies")
    print(f"\n{len(out)} independent authorization-soundness classes (component:mechanism):")
    for name,c in out.items():
        print(f"  [{name}]  gw={c['gateways']} fw={c['frameworks']} "
              f"prof={c['profiles']} pol={c['policies']} kinds={c['kinds']} ntopo={len(c['topologies'])}")
    print(f"\nwrote {ANA}/violations_all.csv, by_topology.csv, classes.json")

if __name__=="__main__":
    main()
